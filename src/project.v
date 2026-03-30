/*
 * PRESENT-80 Block Cipher - Tiny Tapeout Wrapper
 * SPDX-License-Identifier: Apache-2.0
 *
 * Serial 8-bit interface for the PRESENT-80 cipher.
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
 *   3. Assert cmd=11       to start encryption (~33 cycles)
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

    // Active-high reset for cipher
    wire rst = ~rst_n;

    // Command input
    wire [1:0] cmd = uio_in[1:0];

    // --- Serial load shift registers ---
    reg [79:0] key_sr;
    reg [63:0] pt_sr;
    reg [3:0]  key_count;   // 0..10
    reg [3:0]  pt_count;    // 0..8
    reg [3:0]  ct_count;    // 0..7

    wire key_loaded = (key_count == 4'd10);
    wire pt_loaded  = (pt_count == 4'd8);

    // --- Cipher interface ---
    reg         start_cipher;
    wire [63:0] ciphertext;
    wire        cipher_done;

    reg busy;
    reg done;

    present_cipher u_cipher (
        .clk       (clk),
        .rst       (rst),
        .start     (start_cipher),
        .plaintext (pt_sr),
        .key       (key_sr),
        .ciphertext(ciphertext),
        .done      (cipher_done)
    );

    // --- Ciphertext byte mux (MSB first) ---
    reg [7:0] ct_byte;
    always @(*) begin
        case (ct_count[2:0])
            3'd0: ct_byte = ciphertext[63:56];
            3'd1: ct_byte = ciphertext[55:48];
            3'd2: ct_byte = ciphertext[47:40];
            3'd3: ct_byte = ciphertext[39:32];
            3'd4: ct_byte = ciphertext[31:24];
            3'd5: ct_byte = ciphertext[23:16];
            3'd6: ct_byte = ciphertext[15: 8];
            3'd7: ct_byte = ciphertext[ 7: 0];
        endcase
    end

    assign uo_out = ct_byte;

    // --- Bidirectional I/O ---
    // [1:0] input (cmd), [7:2] output (status)
    assign uio_oe  = 8'b11111100;
    assign uio_out = {2'b00, pt_loaded, key_loaded, done, busy, 2'b00};

    // Suppress unused-input warnings
    wire _unused = &{ena, uio_in[7:2], 1'b0};

    // --- Control state machine ---
    always @(posedge clk) begin
        if (rst) begin
            key_sr       <= 80'b0;
            pt_sr        <= 64'b0;
            key_count    <= 4'd0;
            pt_count     <= 4'd0;
            ct_count     <= 4'd0;
            start_cipher <= 1'b0;
            busy         <= 1'b0;
            done         <= 1'b0;
        end else begin
            start_cipher <= 1'b0;

            if (start_cipher) begin
                // Skip one cycle: cipher is clearing its done flag
            end else if (busy) begin
                // Wait for cipher to finish
                if (cipher_done) begin
                    busy     <= 1'b0;
                    done     <= 1'b1;
                    ct_count <= 4'd0;
                end
            end else begin
                case (cmd)
                    2'b01: begin
                        // Load key byte (shift in MSB first)
                        if (!key_loaded) begin
                            key_sr    <= {key_sr[71:0], ui_in};
                            key_count <= key_count + 4'd1;
                        end
                    end
                    2'b10: begin
                        // Load plaintext byte (shift in MSB first)
                        if (!pt_loaded) begin
                            pt_sr    <= {pt_sr[55:0], ui_in};
                            pt_count <= pt_count + 4'd1;
                        end
                    end
                    2'b11: begin
                        if (done) begin
                            // Reading ciphertext bytes
                            if (ct_count == 4'd7) begin
                                // Last byte read, reset for next operation
                                done      <= 1'b0;
                                key_count <= 4'd0;
                                pt_count  <= 4'd0;
                                ct_count  <= 4'd0;
                            end else begin
                                ct_count <= ct_count + 4'd1;
                            end
                        end else if (key_loaded && pt_loaded) begin
                            // Start encryption
                            start_cipher <= 1'b1;
                            busy         <= 1'b1;
                        end
                    end
                    default: ; // NOP
                endcase
            end
        end
    end

endmodule
