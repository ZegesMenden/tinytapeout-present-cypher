/*
 * PRESENT-80 Block Cipher - Tiny Tapeout Wrapper (area-optimized)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Merges serial I/O and cipher into one module so that key_reg and
 * state_reg serve triple duty: serial load, cipher computation, and
 * serial readout.  Eliminates 144 duplicate flip-flops vs. the
 * two-module design.
 *
 * ui_in[7:0]  — data input bus (key or plaintext bytes, MSB first)
 * uo_out[7:0] — data output bus (ciphertext bytes, MSB first)
 *
 * uio[1:0]  (input)  — command:
 *     2'b00 = NOP
 *     2'b01 = load key byte from ui_in      (10 bytes, MSB first)
 *     2'b10 = load plaintext byte from ui_in ( 8 bytes, MSB first)
 *     2'b11 = start encryption / read next ciphertext byte
 * uio[2]    (output) — busy  (encryption in progress)
 * uio[3]    (output) — done  (ciphertext ready)
 * uio[4]    (output) — key_loaded   (all 10 key bytes received)
 * uio[5]    (output) — pt_loaded    (all 8 plaintext bytes received)
 * uio[7:6]  (output) — unused, driven 0
 *
 * Usage:
 *   1. Load 10 key bytes   with cmd=01, one per clock cycle
 *   2. Load 8 PT bytes     with cmd=10, one per clock cycle
 *   3. Assert cmd=11       to start encryption (~32 cycles)
 *   4. When done=1, byte 0 is on uo_out. Pulse cmd=11 to advance
 *      through bytes 1-7. One more cmd=11 resets for next operation.
 */

`default_nettype none

module tt_um_example (
    input  wire [7:0] ui_in,
    output wire [7:0] uo_out,
    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,
    input  wire       ena,
    input  wire       clk,
    input  wire       rst_n
);

    wire rst = ~rst_n;
    wire [1:0] cmd = uio_in[1:0];

    // --- Shared registers: serial I/O + cipher working state ---
    reg [79:0] key_reg;
    reg [63:0] state_reg;

    reg [3:0]  key_count;     // 0..10
    reg [3:0]  pt_count;      // 0..8
    reg [3:0]  ct_count;      // 0..7
    reg [5:0]  round_counter; // 1..32

    reg busy;
    reg done;

    wire key_loaded = (key_count == 4'd10);
    wire pt_loaded  = (pt_count == 4'd8);

    // --- Round key: top 64 bits of key register ---
    wire [63:0] round_key = key_reg[79:16];

    // --- S-box layer on state XOR round key ---
    wire [63:0] state_xor_key = state_reg ^ round_key;
    wire [63:0] state_after_sbox;

    genvar gi;
    generate
        for (gi = 0; gi < 16; gi = gi + 1) begin : sbox_gen
            present_sbox u_sbox (
                .in  (state_xor_key[4*gi+3 : 4*gi]),
                .out (state_after_sbox[4*gi+3 : 4*gi])
            );
        end
    endgenerate

    // --- Permutation layer ---
    wire [63:0] state_after_perm;
    present_player u_player (
        .in  (state_after_sbox),
        .out (state_after_perm)
    );

    // --- Key schedule ---
    wire [79:0] key_rotated   = {key_reg[18:0], key_reg[79:19]};
    wire [3:0]  key_sbox_out;
    present_sbox u_key_sbox (
        .in  (key_rotated[79:76]),
        .out (key_sbox_out)
    );
    wire [79:0] key_after_sbox = {key_sbox_out, key_rotated[75:0]};
    wire [79:0] key_updated    = key_after_sbox ^ ({74'b0, round_counter} << 15);

    // --- CT byte mux (MSB first) ---
    reg [7:0] ct_byte;
    always @(*) begin
        case (ct_count[2:0])
            3'd0: ct_byte = state_reg[63:56];
            3'd1: ct_byte = state_reg[55:48];
            3'd2: ct_byte = state_reg[47:40];
            3'd3: ct_byte = state_reg[39:32];
            3'd4: ct_byte = state_reg[31:24];
            3'd5: ct_byte = state_reg[23:16];
            3'd6: ct_byte = state_reg[15: 8];
            3'd7: ct_byte = state_reg[ 7: 0];
        endcase
    end

    assign uo_out  = ct_byte;
    assign uio_oe  = 8'b11111100;
    assign uio_out = {2'b00, pt_loaded, key_loaded, done, busy, 2'b00};

    wire _unused = &{ena, uio_in[7:2], 1'b0};

    // --- Unified control + datapath ---
    always @(posedge clk) begin
        if (rst) begin
            key_reg       <= 80'b0;
            state_reg     <= 64'b0;
            key_count     <= 4'd0;
            pt_count      <= 4'd0;
            ct_count      <= 4'd0;
            round_counter <= 6'd0;
            busy          <= 1'b0;
            done          <= 1'b0;
        end else if (busy) begin
            if (round_counter <= 6'd31) begin
                // Rounds 1..31: addRoundKey + sBox + pLayer
                state_reg     <= state_after_perm;
                key_reg       <= key_updated;
                round_counter <= round_counter + 6'd1;
            end else begin
                // Round 32: final addRoundKey only
                state_reg <= state_reg ^ round_key;
                busy      <= 1'b0;
                done      <= 1'b1;
                ct_count  <= 4'd0;
            end
        end else begin
            case (cmd)
                2'b01: begin
                    if (!key_loaded) begin
                        key_reg   <= {key_reg[71:0], ui_in};
                        key_count <= key_count + 4'd1;
                    end
                end
                2'b10: begin
                    if (!pt_loaded) begin
                        state_reg <= {state_reg[55:0], ui_in};
                        pt_count  <= pt_count + 4'd1;
                    end
                end
                2'b11: begin
                    if (done) begin
                        if (ct_count == 4'd7) begin
                            done      <= 1'b0;
                            key_count <= 4'd0;
                            pt_count  <= 4'd0;
                            ct_count  <= 4'd0;
                        end else begin
                            ct_count <= ct_count + 4'd1;
                        end
                    end else if (key_loaded && pt_loaded) begin
                        busy          <= 1'b1;
                        round_counter <= 6'd1;
                    end
                end
                default: ;
            endcase
        end
    end

endmodule
