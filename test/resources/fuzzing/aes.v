module aes_cipher_control (
	clk_i,
	rst_ni,
	in_valid_i,
	in_ready_o,
	out_valid_o,
	out_ready_i,
	cfg_valid_i,
	op_i,
	key_len_i,
	crypt_i,
	crypt_o,
	dec_key_gen_i,
	dec_key_gen_o,
	key_clear_i,
	key_clear_o,
	data_out_clear_i,
	data_out_clear_o,
	prng_update_o,
	prng_reseed_req_o,
	prng_reseed_ack_i,
	state_sel_o,
	state_we_o,
	add_rk_sel_o,
	key_expand_op_o,
	key_full_sel_o,
	key_full_we_o,
	key_dec_sel_o,
	key_dec_we_o,
	key_expand_step_o,
	key_expand_clear_o,
	key_expand_round_o,
	key_words_sel_o,
	round_key_sel_o
);
	parameter [0:0] Masking = 0;
	input wire clk_i;
	input wire rst_ni;
	input wire in_valid_i;
	output reg in_ready_o;
	output reg out_valid_o;
	input wire out_ready_i;
	input wire cfg_valid_i;
	input wire op_i;
	input wire [2:0] key_len_i;
	input wire crypt_i;
	output wire crypt_o;
	input wire dec_key_gen_i;
	output wire dec_key_gen_o;
	input wire key_clear_i;
	output wire key_clear_o;
	input wire data_out_clear_i;
	output wire data_out_clear_o;
	output reg prng_update_o;
	output reg prng_reseed_req_o;
	input wire prng_reseed_ack_i;
	output reg [1:0] state_sel_o;
	output reg state_we_o;
	output reg [1:0] add_rk_sel_o;
	output wire key_expand_op_o;
	output reg [1:0] key_full_sel_o;
	output reg key_full_we_o;
	output reg key_dec_sel_o;
	output reg key_dec_we_o;
	output reg key_expand_step_o;
	output reg key_expand_clear_o;
	output wire [3:0] key_expand_round_o;
	output reg [1:0] key_words_sel_o;
	output reg round_key_sel_o;
	reg [2:0] aes_cipher_ctrl_ns;
	reg [2:0] aes_cipher_ctrl_cs;
	reg [3:0] round_d;
	reg [3:0] round_q;
	reg [3:0] num_rounds_d;
	reg [3:0] num_rounds_q;
	wire [3:0] num_rounds_regular;
	reg crypt_d;
	reg crypt_q;
	reg dec_key_gen_d;
	reg dec_key_gen_q;
	reg key_clear_d;
	reg key_clear_q;
	reg data_out_clear_d;
	reg data_out_clear_q;
	reg prng_reseed_done_d;
	reg prng_reseed_done_q;
	wire unused_cfg_valid;
	assign unused_cfg_valid = cfg_valid_i;
	always @(*) begin : aes_cipher_ctrl_fsm
		in_ready_o = 1'b0;
		out_valid_o = 1'b0;
		prng_update_o = 1'b0;
		prng_reseed_req_o = 1'b0;
		state_sel_o = 2'd1;
		state_we_o = 1'b0;
		add_rk_sel_o = 2'd1;
		key_full_sel_o = 2'd2;
		key_full_we_o = 1'b0;
		key_dec_sel_o = 1'd0;
		key_dec_we_o = 1'b0;
		key_expand_step_o = 1'b0;
		key_expand_clear_o = 1'b0;
		key_words_sel_o = 2'd3;
		round_key_sel_o = 1'd0;
		aes_cipher_ctrl_ns = aes_cipher_ctrl_cs;
		round_d = round_q;
		num_rounds_d = num_rounds_q;
		crypt_d = crypt_q;
		dec_key_gen_d = dec_key_gen_q;
		key_clear_d = key_clear_q;
		data_out_clear_d = data_out_clear_q;
		prng_reseed_done_d = prng_reseed_done_q | prng_reseed_ack_i;
		case (aes_cipher_ctrl_cs)
			3'd0: begin
				dec_key_gen_d = 1'b0;
				in_ready_o = 1'b1;
				if (in_valid_i)
					if (key_clear_i || data_out_clear_i) begin
						key_clear_d = key_clear_i;
						data_out_clear_d = data_out_clear_i;
						aes_cipher_ctrl_ns = (data_out_clear_i ? 3'd4 : 3'd5);
					end
					else if (dec_key_gen_i || crypt_i) begin
						crypt_d = ~dec_key_gen_i;
						dec_key_gen_d = dec_key_gen_i;
						state_sel_o = (dec_key_gen_d ? 2'd2 : 2'd0);
						state_we_o = 1'b1;
						prng_update_o = (dec_key_gen_d ? 1'b0 : Masking);
						key_expand_clear_o = 1'b1;
						key_full_sel_o = (dec_key_gen_d ? 2'd0 : (op_i == 1'b0 ? 2'd0 : 2'd1));
						key_full_we_o = 1'b1;
						round_d = 1'sb0;
						num_rounds_d = (key_len_i == 3'b001 ? 4'd10 : (key_len_i == 3'b010 ? 4'd12 : 4'd14));
						aes_cipher_ctrl_ns = 3'd1;
					end
			end
			3'd1: begin
				state_we_o = ~dec_key_gen_q;
				add_rk_sel_o = 2'd0;
				key_words_sel_o = (dec_key_gen_q ? 2'd3 : (key_len_i == 3'b001 ? 2'd0 : ((key_len_i == 3'b010) && (op_i == 1'b0) ? 2'd0 : ((key_len_i == 3'b010) && (op_i == 1'b1) ? 2'd1 : ((key_len_i == 3'b100) && (op_i == 1'b0) ? 2'd0 : ((key_len_i == 3'b100) && (op_i == 1'b1) ? 2'd2 : 2'd3))))));
				if (key_len_i != 3'b100) begin
					key_expand_step_o = 1'b1;
					key_full_we_o = 1'b1;
					prng_update_o = Masking;
				end
				prng_reseed_done_d = 1'b0;
				aes_cipher_ctrl_ns = 3'd2;
			end
			3'd2: begin
				state_we_o = ~dec_key_gen_q;
				key_words_sel_o = (dec_key_gen_q ? 2'd3 : (key_len_i == 3'b001 ? 2'd0 : ((key_len_i == 3'b010) && (op_i == 1'b0) ? 2'd1 : ((key_len_i == 3'b010) && (op_i == 1'b1) ? 2'd0 : ((key_len_i == 3'b100) && (op_i == 1'b0) ? 2'd2 : ((key_len_i == 3'b100) && (op_i == 1'b1) ? 2'd0 : 2'd3))))));
				prng_update_o = Masking;
				prng_reseed_req_o = Masking & ~prng_reseed_done_q;
				key_expand_step_o = 1'b1;
				key_full_we_o = 1'b1;
				round_key_sel_o = (op_i == 1'b0 ? 1'd0 : 1'd1);
				round_d = round_q + 4'b0001;
				if (round_q == num_rounds_regular) begin
					aes_cipher_ctrl_ns = 3'd3;
					if (dec_key_gen_q) begin
						key_dec_we_o = 1'b1;
						out_valid_o = (Masking ? prng_reseed_done_q : 1'b1);
						if (out_ready_i) begin
							dec_key_gen_d = 1'b0;
							aes_cipher_ctrl_ns = 3'd0;
						end
					end
				end
			end
			3'd3: begin
				key_words_sel_o = (dec_key_gen_q ? 2'd3 : (key_len_i == 3'b001 ? 2'd0 : ((key_len_i == 3'b010) && (op_i == 1'b0) ? 2'd1 : ((key_len_i == 3'b010) && (op_i == 1'b1) ? 2'd0 : ((key_len_i == 3'b100) && (op_i == 1'b0) ? 2'd2 : ((key_len_i == 3'b100) && (op_i == 1'b1) ? 2'd0 : 2'd3))))));
				add_rk_sel_o = 2'd2;
				out_valid_o = (Masking ? prng_reseed_done_q : 1'b1);
				if (out_ready_i) begin
					state_we_o = 1'b1;
					state_sel_o = 2'd2;
					crypt_d = 1'b0;
					prng_update_o = Masking;
					dec_key_gen_d = 1'b0;
					aes_cipher_ctrl_ns = 3'd0;
				end
			end
			3'd4: begin
				state_we_o = 1'b1;
				state_sel_o = 2'd2;
				aes_cipher_ctrl_ns = 3'd5;
			end
			3'd5: begin
				if (key_clear_q) begin
					key_full_sel_o = 2'd3;
					key_full_we_o = 1'b1;
					key_dec_sel_o = 1'd1;
					key_dec_we_o = 1'b1;
				end
				if (data_out_clear_q) begin
					add_rk_sel_o = 2'd0;
					key_words_sel_o = 2'd3;
					round_key_sel_o = 1'd0;
				end
				out_valid_o = 1'b1;
				if (out_ready_i) begin
					key_clear_d = 1'b0;
					data_out_clear_d = 1'b0;
					aes_cipher_ctrl_ns = 3'd0;
				end
			end
			default: aes_cipher_ctrl_ns = 3'd0;
		endcase
	end
	always @(posedge clk_i or negedge rst_ni) begin : reg_fsm
		if (!rst_ni) begin
			aes_cipher_ctrl_cs <= 3'd0;
			round_q <= 1'sb0;
			num_rounds_q <= 1'sb0;
			crypt_q <= 1'b0;
			dec_key_gen_q <= 1'b0;
			key_clear_q <= 1'b0;
			data_out_clear_q <= 1'b0;
			prng_reseed_done_q <= 1'b0;
		end
		else begin
			aes_cipher_ctrl_cs <= aes_cipher_ctrl_ns;
			round_q <= round_d;
			num_rounds_q <= num_rounds_d;
			crypt_q <= crypt_d;
			dec_key_gen_q <= dec_key_gen_d;
			key_clear_q <= key_clear_d;
			data_out_clear_q <= data_out_clear_d;
			prng_reseed_done_q <= prng_reseed_done_d;
		end
	end
	assign num_rounds_regular = num_rounds_q - 4'd2;
	assign key_expand_op_o = (dec_key_gen_d || dec_key_gen_q ? 1'b0 : op_i);
	assign key_expand_round_o = round_d;
	assign crypt_o = crypt_q;
	assign dec_key_gen_o = dec_key_gen_q;
	assign key_clear_o = key_clear_q;
	assign data_out_clear_o = data_out_clear_q;
endmodule
module aes_cipher_core (
	clk_i,
	rst_ni,
	in_valid_i,
	in_ready_o,
	out_valid_o,
	out_ready_i,
	cfg_valid_i,
	op_i,
	key_len_i,
	crypt_i,
	crypt_o,
	dec_key_gen_i,
	dec_key_gen_o,
	key_clear_i,
	key_clear_o,
	data_out_clear_i,
	data_out_clear_o,
	prd_clearing_i,
	force_zero_masks_i,
	data_in_mask_o,
	entropy_req_o,
	entropy_ack_i,
	entropy_i,
	state_init_i,
	key_init_i,
	state_o
);
	parameter [0:0] AES192Enable = 1;
	parameter [0:0] Masking = 0;
	parameter integer SBoxImpl = 32'sd0;
	parameter [0:0] SecAllowForcingMasks = 0;
	localparam signed [31:0] NumShares = (Masking ? 2 : 1);
	localparam [31:0] aes_pkg_WidthPRDData = 128;
	localparam [31:0] aes_pkg_WidthPRDKey = 32;
	localparam [31:0] aes_pkg_WidthPRDMasking = aes_pkg_WidthPRDData + aes_pkg_WidthPRDKey;
	localparam [aes_pkg_WidthPRDMasking - 1:0] aes_pkg_DefaultSeedMasking = 160'h0000000500000004000000030000000200000001;
	parameter [aes_pkg_WidthPRDMasking - 1:0] SeedMasking = aes_pkg_DefaultSeedMasking;
	input wire clk_i;
	input wire rst_ni;
	input wire in_valid_i;
	output wire in_ready_o;
	output wire out_valid_o;
	input wire out_ready_i;
	input wire cfg_valid_i;
	input wire op_i;
	input wire [2:0] key_len_i;
	input wire crypt_i;
	output wire crypt_o;
	input wire dec_key_gen_i;
	output wire dec_key_gen_o;
	input wire key_clear_i;
	output wire key_clear_o;
	input wire data_out_clear_i;
	output wire data_out_clear_o;
	localparam [31:0] aes_pkg_WidthPRDClearing = 64;
	input wire [63:0] prd_clearing_i;
	input wire force_zero_masks_i;
	output wire [127:0] data_in_mask_o;
	output wire entropy_req_o;
	input wire entropy_ack_i;
	input wire [aes_pkg_WidthPRDMasking - 1:0] entropy_i;
	input wire [(((NumShares * 4) * 4) * 8) - 1:0] state_init_i;
	input wire [((NumShares * 8) * 32) - 1:0] key_init_i;
	output wire [(((NumShares * 4) * 4) * 8) - 1:0] state_o;
	reg [(((NumShares * 4) * 4) * 8) - 1:0] state_d;
	reg [(((NumShares * 4) * 4) * 8) - 1:0] state_q;
	wire state_we;
	wire [1:0] state_sel;
	wire [127:0] sub_bytes_out;
	wire [127:0] sb_in_mask;
	wire [127:0] sb_out_mask;
	wire [127:0] shift_rows_in [0:NumShares - 1];
	wire [(((NumShares * 4) * 4) * 8) - 1:0] shift_rows_out;
	wire [(((NumShares * 4) * 4) * 8) - 1:0] mix_columns_out;
	reg [(((NumShares * 4) * 4) * 8) - 1:0] add_round_key_in;
	wire [(((NumShares * 4) * 4) * 8) - 1:0] add_round_key_out;
	wire [1:0] add_round_key_in_sel;
	reg [((NumShares * 8) * 32) - 1:0] key_full_d;
	reg [((NumShares * 8) * 32) - 1:0] key_full_q;
	wire key_full_we;
	wire [1:0] key_full_sel;
	reg [((NumShares * 8) * 32) - 1:0] key_dec_d;
	reg [((NumShares * 8) * 32) - 1:0] key_dec_q;
	wire key_dec_we;
	wire key_dec_sel;
	wire [((NumShares * 8) * 32) - 1:0] key_expand_out;
	wire key_expand_op;
	wire key_expand_step;
	wire key_expand_clear;
	wire [3:0] key_expand_round;
	wire [1:0] key_words_sel;
	reg [127:0] key_words [0:NumShares - 1];
	wire [(((NumShares * 4) * 4) * 8) - 1:0] key_bytes;
	wire [(((NumShares * 4) * 4) * 8) - 1:0] key_mix_columns_out;
	reg [(((NumShares * 4) * 4) * 8) - 1:0] round_key;
	wire round_key_sel;
	wire [127:0] prd_clearing_128;
	wire [255:0] prd_clearing_256;
	wire [aes_pkg_WidthPRDMasking - 1:0] prd_masking;
	wire [31:0] prd_key_expand;
	wire prd_masking_upd;
	wire prd_masking_rsd_req;
	wire prd_masking_rsd_ack;
	localparam [31:0] NumChunks = 2;
	genvar c;
	generate
		for (c = 0; c < NumChunks; c = c + 1) begin : gen_prd_clearing
			assign prd_clearing_128[c * aes_pkg_WidthPRDClearing+:aes_pkg_WidthPRDClearing] = prd_clearing_i;
			assign prd_clearing_256[c * aes_pkg_WidthPRDClearing+:aes_pkg_WidthPRDClearing] = prd_clearing_i;
			assign prd_clearing_256[(c * aes_pkg_WidthPRDClearing) + 128+:aes_pkg_WidthPRDClearing] = prd_clearing_i;
		end
	endgenerate
	always @(*) begin : state_mux
		case (state_sel)
			2'd0: state_d = state_init_i;
			2'd1: state_d = add_round_key_out;
			2'd2: state_d = {NumShares {prd_clearing_128}};
			default: state_d = {NumShares {prd_clearing_128}};
		endcase
	end
	always @(posedge clk_i) begin : state_reg
		if (state_we)
			state_q <= state_d;
	end
	generate
		if (!Masking) begin : gen_no_masks
			assign sb_in_mask = 1'sb0;
			assign prd_masking = 1'sb0;
			wire unused_entropy_ack;
			wire [aes_pkg_WidthPRDMasking - 1:0] unused_entropy;
			assign unused_entropy_ack = entropy_ack_i;
			assign unused_entropy = entropy_i;
			assign entropy_req_o = 1'b0;
			wire unused_force_zero_masks;
			wire unused_prd_masking_upd;
			wire unused_prd_masking_rsd_req;
			assign unused_force_zero_masks = force_zero_masks_i;
			assign unused_prd_masking_upd = prd_masking_upd;
			assign unused_prd_masking_rsd_req = prd_masking_rsd_req;
			assign prd_masking_rsd_ack = 1'b0;
		end
		else begin : gen_masks
			assign sb_in_mask = state_q[8 * (4 * ((NumShares - 2) * 4))+:128];
			aes_prng_masking #(
				.Width(aes_pkg_WidthPRDMasking),
				.SecAllowForcingMasks(SecAllowForcingMasks),
				.DefaultSeed(SeedMasking)
			) u_aes_prng_masking(
				.clk_i(clk_i),
				.rst_ni(rst_ni),
				.force_zero_masks_i(force_zero_masks_i),
				.data_update_i(prd_masking_upd),
				.data_o(prd_masking),
				.reseed_req_i(prd_masking_rsd_req),
				.reseed_ack_o(prd_masking_rsd_ack),
				.entropy_req_o(entropy_req_o),
				.entropy_ack_i(entropy_ack_i),
				.entropy_i(entropy_i)
			);
		end
	endgenerate
	assign sb_out_mask = prd_masking[aes_pkg_WidthPRDMasking - 1:aes_pkg_WidthPRDKey];
	assign data_in_mask_o = prd_masking[aes_pkg_WidthPRDMasking - 1-:128];
	assign prd_key_expand = prd_masking[31:0];
	aes_sub_bytes #(.SBoxImpl(SBoxImpl)) u_aes_sub_bytes(
		.op_i(op_i),
		.data_i(state_q[8 * (4 * ((NumShares - 1) * 4))+:128]),
		.in_mask_i(sb_in_mask),
		.out_mask_i(sb_out_mask),
		.data_o(sub_bytes_out)
	);
	genvar s;
	generate
		for (s = 0; s < NumShares; s = s + 1) begin : gen_shares_shift_mix
			if (s == 0) begin : gen_shift_in_data
				assign shift_rows_in[s] = sub_bytes_out;
			end
			else begin : gen_shift_in_mask
				assign shift_rows_in[s] = sb_out_mask;
			end
			aes_shift_rows u_aes_shift_rows(
				.op_i(op_i),
				.data_i(shift_rows_in[s]),
				.data_o(shift_rows_out[8 * (4 * (((NumShares - 1) - s) * 4))+:128])
			);
			aes_mix_columns u_aes_mix_columns(
				.op_i(op_i),
				.data_i(shift_rows_out[8 * (4 * (((NumShares - 1) - s) * 4))+:128]),
				.data_o(mix_columns_out[8 * (4 * (((NumShares - 1) - s) * 4))+:128])
			);
		end
	endgenerate
	always @(*) begin : add_round_key_in_mux
		case (add_round_key_in_sel)
			2'd0: add_round_key_in = state_q;
			2'd1: add_round_key_in = mix_columns_out;
			2'd2: add_round_key_in = shift_rows_out;
			default: add_round_key_in = state_q;
		endcase
	end
	generate
		for (s = 0; s < NumShares; s = s + 1) begin : gen_shares_add_round_key
			assign add_round_key_out[8 * (4 * (((NumShares - 1) - s) * 4))+:128] = add_round_key_in[8 * (4 * (((NumShares - 1) - s) * 4))+:128] ^ round_key[8 * (4 * (((NumShares - 1) - s) * 4))+:128];
		end
	endgenerate
	always @(*) begin : key_full_mux
		case (key_full_sel)
			2'd0: key_full_d = key_init_i;
			2'd1: key_full_d = key_dec_q;
			2'd2: key_full_d = key_expand_out;
			2'd3: key_full_d = {NumShares {prd_clearing_256}};
			default: key_full_d = {NumShares {prd_clearing_256}};
		endcase
	end
	always @(posedge clk_i) begin : key_full_reg
		if (key_full_we)
			key_full_q <= key_full_d;
	end
	always @(*) begin : key_dec_mux
		case (key_dec_sel)
			1'd0: key_dec_d = key_expand_out;
			1'd1: key_dec_d = {NumShares {prd_clearing_256}};
			default: key_dec_d = {NumShares {prd_clearing_256}};
		endcase
	end
	always @(posedge clk_i) begin : key_dec_reg
		if (key_dec_we)
			key_dec_q <= key_dec_d;
	end
	aes_key_expand #(
		.AES192Enable(AES192Enable),
		.Masking(Masking),
		.SBoxImpl(SBoxImpl)
	) u_aes_key_expand(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.cfg_valid_i(cfg_valid_i),
		.op_i(key_expand_op),
		.step_i(key_expand_step),
		.clear_i(key_expand_clear),
		.round_i(key_expand_round),
		.key_len_i(key_len_i),
		.key_i(key_full_q),
		.key_o(key_expand_out),
		.prd_masking_i(prd_key_expand)
	);
	function automatic [127:0] aes_pkg_aes_transpose;
		input reg [127:0] in;
		reg [127:0] transpose;
		begin
			transpose = 1'sb0;
			begin : sv2v_autoblock_1
				reg signed [31:0] j;
				for (j = 0; j < 4; j = j + 1)
					begin : sv2v_autoblock_2
						reg signed [31:0] i;
						for (i = 0; i < 4; i = i + 1)
							transpose[((i * 4) + j) * 8+:8] = in[((j * 4) + i) * 8+:8];
					end
			end
			aes_pkg_aes_transpose = transpose;
		end
	endfunction
	generate
		for (s = 0; s < NumShares; s = s + 1) begin : gen_shares_round_key
			always @(*) begin : key_words_mux
				case (key_words_sel)
					2'd0: key_words[s] = key_full_q[32 * (((NumShares - 1) - s) * 8)+:128];
					2'd1: key_words[s] = (AES192Enable ? key_full_q[32 * ((((NumShares - 1) - s) * 8) + 2)+:128] : {128 {1'sb0}});
					2'd2: key_words[s] = key_full_q[32 * ((((NumShares - 1) - s) * 8) + 4)+:128];
					2'd3: key_words[s] = 1'sb0;
					default: key_words[s] = 1'sb0;
				endcase
			end
			assign key_bytes[8 * (4 * (((NumShares - 1) - s) * 4))+:128] = aes_pkg_aes_transpose(key_words[s]);
			aes_mix_columns u_aes_key_mix_columns(
				.op_i(1'b1),
				.data_i(key_bytes[8 * (4 * (((NumShares - 1) - s) * 4))+:128]),
				.data_o(key_mix_columns_out[8 * (4 * (((NumShares - 1) - s) * 4))+:128])
			);
		end
	endgenerate
	always @(*) begin : round_key_mux
		case (round_key_sel)
			1'd0: round_key = key_bytes;
			1'd1: round_key = key_mix_columns_out;
			default: round_key = key_bytes;
		endcase
	end
	aes_cipher_control #(.Masking(Masking)) u_aes_cipher_control(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.in_valid_i(in_valid_i),
		.in_ready_o(in_ready_o),
		.out_valid_o(out_valid_o),
		.out_ready_i(out_ready_i),
		.cfg_valid_i(cfg_valid_i),
		.op_i(op_i),
		.key_len_i(key_len_i),
		.crypt_i(crypt_i),
		.crypt_o(crypt_o),
		.dec_key_gen_i(dec_key_gen_i),
		.dec_key_gen_o(dec_key_gen_o),
		.key_clear_i(key_clear_i),
		.key_clear_o(key_clear_o),
		.data_out_clear_i(data_out_clear_i),
		.data_out_clear_o(data_out_clear_o),
		.prng_update_o(prd_masking_upd),
		.prng_reseed_req_o(prd_masking_rsd_req),
		.prng_reseed_ack_i(prd_masking_rsd_ack),
		.state_sel_o(state_sel),
		.state_we_o(state_we),
		.add_rk_sel_o(add_round_key_in_sel),
		.key_expand_op_o(key_expand_op),
		.key_full_sel_o(key_full_sel),
		.key_full_we_o(key_full_we),
		.key_dec_sel_o(key_dec_sel),
		.key_dec_we_o(key_dec_we),
		.key_expand_step_o(key_expand_step),
		.key_expand_clear_o(key_expand_clear),
		.key_expand_round_o(key_expand_round),
		.key_words_sel_o(key_words_sel),
		.round_key_sel_o(round_key_sel)
	);
	assign state_o = add_round_key_out;
	initial begin : AesMaskedCoreAndSBox
		
	end
endmodule
module aes_control (
	clk_i,
	rst_ni,
	ctrl_qe_i,
	ctrl_we_o,
	ctrl_err_storage_i,
	op_i,
	mode_i,
	cipher_op_i,
	manual_operation_i,
	start_i,
	key_clear_i,
	iv_clear_i,
	data_in_clear_i,
	data_out_clear_i,
	prng_reseed_i,
	key_init_qe_i,
	iv_qe_i,
	data_in_qe_i,
	data_out_re_i,
	data_in_we_o,
	data_out_we_o,
	data_in_prev_sel_o,
	data_in_prev_we_o,
	state_in_sel_o,
	add_state_in_sel_o,
	add_state_out_sel_o,
	ctr_incr_o,
	ctr_ready_i,
	ctr_we_i,
	cipher_in_valid_o,
	cipher_in_ready_i,
	cipher_out_valid_i,
	cipher_out_ready_o,
	cipher_crypt_o,
	cipher_crypt_i,
	cipher_dec_key_gen_o,
	cipher_dec_key_gen_i,
	cipher_key_clear_o,
	cipher_key_clear_i,
	cipher_data_out_clear_o,
	cipher_data_out_clear_i,
	key_init_sel_o,
	key_init_we_o,
	iv_sel_o,
	iv_we_o,
	prng_data_req_o,
	prng_data_ack_i,
	prng_reseed_req_o,
	prng_reseed_ack_i,
	start_o,
	start_we_o,
	key_clear_o,
	key_clear_we_o,
	iv_clear_o,
	iv_clear_we_o,
	data_in_clear_o,
	data_in_clear_we_o,
	data_out_clear_o,
	data_out_clear_we_o,
	prng_reseed_o,
	prng_reseed_we_o,
	output_valid_o,
	output_valid_we_o,
	input_ready_o,
	input_ready_we_o,
	idle_o,
	idle_we_o,
	stall_o,
	stall_we_o
);
	parameter [31:0] SecStartTriggerDelay = 0;
	input wire clk_i;
	input wire rst_ni;
	input wire ctrl_qe_i;
	output reg ctrl_we_o;
	input wire ctrl_err_storage_i;
	input wire op_i;
	input wire [5:0] mode_i;
	input wire cipher_op_i;
	input wire manual_operation_i;
	input wire start_i;
	input wire key_clear_i;
	input wire iv_clear_i;
	input wire data_in_clear_i;
	input wire data_out_clear_i;
	input wire prng_reseed_i;
	input wire [15:0] key_init_qe_i;
	input wire [3:0] iv_qe_i;
	input wire [3:0] data_in_qe_i;
	input wire [3:0] data_out_re_i;
	output reg data_in_we_o;
	output reg data_out_we_o;
	output reg data_in_prev_sel_o;
	output reg data_in_prev_we_o;
	output reg state_in_sel_o;
	output reg add_state_in_sel_o;
	output reg [2:0] add_state_out_sel_o;
	output reg ctr_incr_o;
	input wire ctr_ready_i;
	input wire [7:0] ctr_we_i;
	output reg cipher_in_valid_o;
	input wire cipher_in_ready_i;
	input wire cipher_out_valid_i;
	output reg cipher_out_ready_o;
	output reg cipher_crypt_o;
	input wire cipher_crypt_i;
	output reg cipher_dec_key_gen_o;
	input wire cipher_dec_key_gen_i;
	output reg cipher_key_clear_o;
	input wire cipher_key_clear_i;
	output reg cipher_data_out_clear_o;
	input wire cipher_data_out_clear_i;
	output reg key_init_sel_o;
	output reg [15:0] key_init_we_o;
	output reg [2:0] iv_sel_o;
	output reg [7:0] iv_we_o;
	output reg prng_data_req_o;
	input wire prng_data_ack_i;
	output reg prng_reseed_req_o;
	input wire prng_reseed_ack_i;
	output wire start_o;
	output reg start_we_o;
	output wire key_clear_o;
	output reg key_clear_we_o;
	output wire iv_clear_o;
	output reg iv_clear_we_o;
	output wire data_in_clear_o;
	output reg data_in_clear_we_o;
	output wire data_out_clear_o;
	output reg data_out_clear_we_o;
	output wire prng_reseed_o;
	output reg prng_reseed_we_o;
	output wire output_valid_o;
	output wire output_valid_we_o;
	output wire input_ready_o;
	output wire input_ready_we_o;
	output reg idle_o;
	output reg idle_we_o;
	output reg stall_o;
	output reg stall_we_o;
	reg [2:0] aes_ctrl_ns;
	reg [2:0] aes_ctrl_cs;
	reg key_init_clear;
	wire key_init_new;
	reg key_init_load;
	reg key_init_arm;
	wire key_init_ready;
	wire [7:0] iv_qe;
	reg iv_clear;
	reg iv_load;
	reg iv_arm;
	wire iv_ready;
	wire [3:0] data_in_new_d;
	reg [3:0] data_in_new_q;
	wire data_in_new;
	reg data_in_load;
	wire [3:0] data_out_read_d;
	reg [3:0] data_out_read_q;
	wire data_out_read;
	reg output_valid_q;
	wire start_trigger;
	wire cfg_valid;
	wire start;
	wire finish;
	wire cipher_crypt;
	reg cipher_out_done;
	wire doing_cbc_enc;
	wire doing_cbc_dec;
	wire doing_cfb_enc;
	wire doing_cfb_dec;
	wire doing_ofb;
	wire doing_ctr;
	reg ctrl_we_q;
	wire clear_in_out_status;
	generate
		if (SecStartTriggerDelay > 0) begin : gen_start_delay
			localparam [31:0] WidthCounter = $clog2(SecStartTriggerDelay + 1);
			wire [WidthCounter - 1:0] count_d;
			reg [WidthCounter - 1:0] count_q;
			assign count_d = (!start_i ? {WidthCounter {1'sb0}} : (start_trigger ? count_q : count_q + 1'b1));
			assign start_trigger = (count_q == SecStartTriggerDelay[WidthCounter - 1:0] ? 1'b1 : 1'b0);
			always @(posedge clk_i or negedge rst_ni)
				if (!rst_ni)
					count_q <= 1'sb0;
				else
					count_q <= count_d;
		end
		else begin : gen_no_start_delay
			assign start_trigger = start_i;
		end
	endgenerate
	assign iv_qe = {iv_qe_i[3], iv_qe_i[3], iv_qe_i[2], iv_qe_i[2], iv_qe_i[1], iv_qe_i[1], iv_qe_i[0], iv_qe_i[0]};
	assign cfg_valid = ~((mode_i == 6'b100000) | ctrl_err_storage_i);
	assign start = cfg_valid & (manual_operation_i ? start_trigger : (mode_i == 6'b000001 ? key_init_ready & data_in_new : (mode_i == 6'b000010 ? (key_init_ready & data_in_new) & iv_ready : (mode_i == 6'b000100 ? (key_init_ready & data_in_new) & iv_ready : (mode_i == 6'b001000 ? (key_init_ready & data_in_new) & iv_ready : (mode_i == 6'b010000 ? ((key_init_ready & data_in_new) & iv_ready) & ctr_ready_i : 1'b0))))));
	assign finish = cfg_valid & (manual_operation_i ? 1'b1 : ~output_valid_q | data_out_read);
	assign cipher_crypt = cipher_crypt_o | cipher_crypt_i;
	assign doing_cbc_enc = (cipher_crypt & (mode_i == 6'b000010)) & (op_i == 1'b0);
	assign doing_cbc_dec = (cipher_crypt & (mode_i == 6'b000010)) & (op_i == 1'b1);
	assign doing_cfb_enc = (cipher_crypt & (mode_i == 6'b000100)) & (op_i == 1'b0);
	assign doing_cfb_dec = (cipher_crypt & (mode_i == 6'b000100)) & (op_i == 1'b1);
	assign doing_ofb = cipher_crypt & (mode_i == 6'b001000);
	assign doing_ctr = cipher_crypt & (mode_i == 6'b010000);
	always @(*) begin : aes_ctrl_fsm
		data_in_prev_sel_o = 1'd1;
		data_in_prev_we_o = 1'b0;
		state_in_sel_o = 1'd1;
		add_state_in_sel_o = 1'd0;
		add_state_out_sel_o = 3'd0;
		ctr_incr_o = 1'b0;
		cipher_in_valid_o = 1'b0;
		cipher_out_ready_o = 1'b0;
		cipher_out_done = 1'b0;
		cipher_crypt_o = 1'b0;
		cipher_dec_key_gen_o = 1'b0;
		cipher_key_clear_o = 1'b0;
		cipher_data_out_clear_o = 1'b0;
		key_init_sel_o = 1'd0;
		key_init_we_o = 16'h0000;
		iv_sel_o = 3'd0;
		iv_we_o = 8'h00;
		ctrl_we_o = 1'b0;
		prng_data_req_o = 1'b0;
		prng_reseed_req_o = 1'b0;
		start_we_o = 1'b0;
		key_clear_we_o = 1'b0;
		iv_clear_we_o = 1'b0;
		data_in_clear_we_o = 1'b0;
		data_out_clear_we_o = 1'b0;
		prng_reseed_we_o = 1'b0;
		idle_o = 1'b0;
		idle_we_o = 1'b0;
		stall_o = 1'b0;
		stall_we_o = 1'b0;
		data_in_load = 1'b0;
		data_in_we_o = 1'b0;
		data_out_we_o = 1'b0;
		key_init_clear = 1'b0;
		key_init_load = 1'b0;
		key_init_arm = 1'b0;
		iv_clear = 1'b0;
		iv_load = 1'b0;
		iv_arm = 1'b0;
		aes_ctrl_ns = aes_ctrl_cs;
		case (aes_ctrl_cs)
			3'd0: begin
				idle_o = (((((start || key_clear_i) || iv_clear_i) || data_in_clear_i) || data_out_clear_i) || prng_reseed_i ? 1'b0 : 1'b1);
				idle_we_o = 1'b1;
				if (idle_o) begin
					key_init_we_o = key_init_qe_i;
					iv_we_o = iv_qe;
					ctrl_we_o = (!ctrl_err_storage_i ? ctrl_qe_i : 1'b0);
					key_init_clear = ctrl_we_o;
					iv_clear = ctrl_we_o;
				end
				if (prng_reseed_i) begin
					prng_reseed_req_o = 1'b1;
					if (prng_reseed_ack_i)
						prng_reseed_we_o = 1'b1;
				end
				else if (((key_clear_i || data_out_clear_i) || iv_clear_i) || data_in_clear_i)
					aes_ctrl_ns = 3'd2;
				else if (start) begin
					cipher_crypt_o = 1'b1;
					cipher_dec_key_gen_o = key_init_new & (cipher_op_i == 1'b1);
					data_in_prev_sel_o = (doing_cbc_dec ? 1'd0 : (doing_cfb_enc ? 1'd0 : (doing_cfb_dec ? 1'd0 : (doing_ofb ? 1'd0 : (doing_ctr ? 1'd0 : 1'd1)))));
					data_in_prev_we_o = (doing_cbc_dec ? 1'b1 : (doing_cfb_enc ? 1'b1 : (doing_cfb_dec ? 1'b1 : (doing_ofb ? 1'b1 : (doing_ctr ? 1'b1 : 1'b0)))));
					state_in_sel_o = (doing_cfb_enc ? 1'd0 : (doing_cfb_dec ? 1'd0 : (doing_ofb ? 1'd0 : (doing_ctr ? 1'd0 : 1'd1))));
					add_state_in_sel_o = (doing_cbc_enc ? 1'd1 : (doing_cfb_enc ? 1'd1 : (doing_cfb_dec ? 1'd1 : (doing_ofb ? 1'd1 : (doing_ctr ? 1'd1 : 1'd0)))));
					cipher_in_valid_o = 1'b1;
					if (cipher_in_ready_i) begin
						start_we_o = ~cipher_dec_key_gen_o;
						aes_ctrl_ns = 3'd1;
					end
				end
			end
			3'd1: begin
				key_init_load = cipher_dec_key_gen_i;
				key_init_arm = ~cipher_dec_key_gen_i;
				iv_load = ~cipher_dec_key_gen_i & (((((doing_cbc_enc | doing_cbc_dec) | doing_cfb_enc) | doing_cfb_dec) | doing_ofb) | doing_ctr);
				data_in_load = ~cipher_dec_key_gen_i;
				ctr_incr_o = (doing_ctr ? 1'b1 : 1'b0);
				aes_ctrl_ns = (~cipher_dec_key_gen_i ? 3'd2 : 3'd3);
			end
			3'd2: begin
				iv_sel_o = (doing_ctr ? 3'd4 : 3'd0);
				iv_we_o = (doing_ctr ? ctr_we_i : 8'h00);
				prng_data_req_o = 1'b1;
				if (prng_data_ack_i)
					if (cipher_crypt_i)
						aes_ctrl_ns = 3'd3;
					else if (key_clear_i || data_out_clear_i) begin
						cipher_key_clear_o = key_clear_i;
						cipher_data_out_clear_o = data_out_clear_i;
						cipher_in_valid_o = 1'b1;
						if (cipher_in_ready_i)
							aes_ctrl_ns = 3'd4;
					end
					else
						aes_ctrl_ns = 3'd4;
			end
			3'd3:
				if (cipher_dec_key_gen_i) begin
					cipher_out_ready_o = 1'b1;
					if (cipher_out_valid_i)
						aes_ctrl_ns = 3'd0;
				end
				else begin
					cipher_out_ready_o = finish;
					cipher_out_done = finish & cipher_out_valid_i;
					stall_o = ~finish & cipher_out_valid_i;
					stall_we_o = 1'b1;
					add_state_out_sel_o = (doing_cbc_dec ? 3'd1 : (doing_cfb_enc ? 3'd2 : (doing_cfb_dec ? 3'd2 : (doing_ofb ? 3'd2 : (doing_ctr ? 3'd2 : 3'd0)))));
					iv_sel_o = (doing_cbc_enc ? 3'd1 : (doing_cbc_dec ? 3'd3 : (doing_cfb_enc ? 3'd1 : (doing_cfb_dec ? 3'd3 : (doing_ofb ? 3'd2 : (doing_ctr ? 3'd4 : 3'd0))))));
					iv_we_o = ((((doing_cbc_enc || doing_cbc_dec) || doing_cfb_enc) || doing_cfb_dec) || doing_ofb ? {8 {cipher_out_done}} : (doing_ctr ? ctr_we_i : 8'h00));
					iv_arm = (((((doing_cbc_enc || doing_cbc_dec) || doing_cfb_enc) || doing_cfb_dec) || doing_ofb) || doing_ctr ? cipher_out_done : 1'b0);
					if (cipher_out_done) begin
						data_out_we_o = 1'b1;
						aes_ctrl_ns = 3'd0;
					end
				end
			3'd4: begin
				if (iv_clear_i) begin
					iv_sel_o = 3'd5;
					iv_we_o = 8'hff;
					iv_clear_we_o = 1'b1;
					iv_clear = 1'b1;
				end
				if (data_in_clear_i) begin
					data_in_we_o = 1'b1;
					data_in_clear_we_o = 1'b1;
					data_in_prev_sel_o = 1'd1;
					data_in_prev_we_o = 1'b1;
				end
				if (cipher_key_clear_i || cipher_data_out_clear_i) begin
					cipher_out_ready_o = 1'b1;
					if (cipher_out_valid_i) begin
						if (cipher_key_clear_i) begin
							key_init_sel_o = 1'd1;
							key_init_we_o = 16'hffff;
							key_clear_we_o = 1'b1;
							key_init_clear = 1'b1;
						end
						if (cipher_data_out_clear_i) begin
							data_out_we_o = 1'b1;
							data_out_clear_we_o = 1'b1;
						end
						aes_ctrl_ns = 3'd0;
					end
				end
				else
					aes_ctrl_ns = 3'd0;
			end
			default: aes_ctrl_ns = 3'd0;
		endcase
	end
	always @(posedge clk_i or negedge rst_ni) begin : reg_fsm
		if (!rst_ni)
			aes_ctrl_cs <= 3'd0;
		else
			aes_ctrl_cs <= aes_ctrl_ns;
	end
	aes_reg_status #(.Width(16)) u_reg_status_key_init(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we_i({key_init_we_o[0+:8], key_init_we_o[8+:8]}),
		.use_i(key_init_load),
		.clear_i(key_init_clear),
		.arm_i(key_init_arm),
		.new_o(key_init_new),
		.clean_o(key_init_ready)
	);
	aes_reg_status #(.Width(8)) u_reg_status_iv(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we_i(iv_we_o),
		.use_i(iv_load),
		.clear_i(iv_clear),
		.arm_i(iv_arm),
		.new_o(iv_ready)
	);
	always @(posedge clk_i or negedge rst_ni) begin : reg_ctrl_we
		if (!rst_ni)
			ctrl_we_q <= 1'b0;
		else
			ctrl_we_q <= ctrl_we_o;
	end
	assign clear_in_out_status = ctrl_we_q;
	assign data_in_new_d = ((data_in_load || data_in_we_o) || clear_in_out_status ? {4 {1'sb0}} : data_in_new_q | data_in_qe_i);
	assign data_in_new = &data_in_new_d;
	assign data_out_read_d = (&data_out_read_q || clear_in_out_status ? {4 {1'sb0}} : data_out_read_q | data_out_re_i);
	assign data_out_read = &data_out_read_d;
	always @(posedge clk_i or negedge rst_ni) begin : reg_edge_detection
		if (!rst_ni) begin
			data_in_new_q <= 1'sb0;
			data_out_read_q <= 1'sb0;
		end
		else begin
			data_in_new_q <= data_in_new_d;
			data_out_read_q <= data_out_read_d;
		end
	end
	assign input_ready_o = ~data_in_new;
	assign input_ready_we_o = ((data_in_new | data_in_load) | data_in_we_o) | clear_in_out_status;
	assign output_valid_o = data_out_we_o & ~data_out_clear_we_o;
	assign output_valid_we_o = ((data_out_we_o | data_out_read) | data_out_clear_we_o) | clear_in_out_status;
	always @(posedge clk_i or negedge rst_ni) begin : reg_output_valid
		if (!rst_ni)
			output_valid_q <= 1'sb0;
		else if (output_valid_we_o)
			output_valid_q <= output_valid_o;
	end
	assign start_o = 1'b0;
	assign key_clear_o = 1'b0;
	assign iv_clear_o = 1'b0;
	assign data_in_clear_o = 1'b0;
	assign data_out_clear_o = 1'b0;
	assign prng_reseed_o = 1'b0;
endmodule
module aes_core (
	clk_i,
	rst_ni,
	entropy_clearing_req_o,
	entropy_clearing_ack_i,
	entropy_clearing_i,
	entropy_masking_req_o,
	entropy_masking_ack_i,
	entropy_masking_i,
	ctrl_err_update_o,
	ctrl_err_storage_o,
	reg2hw,
	hw2reg
);
	parameter [0:0] AES192Enable = 1;
	parameter [0:0] Masking = 0;
	parameter integer SBoxImpl = 32'sd0;
	parameter [31:0] SecStartTriggerDelay = 0;
	parameter [0:0] SecAllowForcingMasks = 0;
	localparam signed [31:0] NumShares = (Masking ? 2 : 1);
	localparam [31:0] aes_pkg_WidthPRDClearing = 64;
	localparam [63:0] aes_pkg_DefaultSeedClearing = 64'hfedcba9876543210;
	parameter [63:0] SeedClearing = aes_pkg_DefaultSeedClearing;
	localparam [31:0] aes_pkg_WidthPRDData = 128;
	localparam [31:0] aes_pkg_WidthPRDKey = 32;
	localparam [31:0] aes_pkg_WidthPRDMasking = aes_pkg_WidthPRDData + aes_pkg_WidthPRDKey;
	localparam [aes_pkg_WidthPRDMasking - 1:0] aes_pkg_DefaultSeedMasking = 160'h0000000500000004000000030000000200000001;
	parameter [aes_pkg_WidthPRDMasking - 1:0] SeedMasking = aes_pkg_DefaultSeedMasking;
	input wire clk_i;
	input wire rst_ni;
	output wire entropy_clearing_req_o;
	input wire entropy_clearing_ack_i;
	input wire [63:0] entropy_clearing_i;
	output wire entropy_masking_req_o;
	input wire entropy_masking_ack_i;
	input wire [aes_pkg_WidthPRDMasking - 1:0] entropy_masking_i;
	output wire ctrl_err_update_o;
	output wire ctrl_err_storage_o;
	input wire [955:0] reg2hw;
	output reg [933:0] hw2reg;
	wire ctrl_re;
	wire ctrl_qe;
	wire ctrl_we;
	wire aes_op_q;
	wire [5:0] mode;
	wire [5:0] aes_mode_q;
	wire cipher_op;
	wire [2:0] key_len;
	wire [2:0] key_len_q;
	wire manual_operation_q;
	wire force_zero_masks_q;
	reg [11:0] ctrl_d;
	wire [11:0] ctrl_q;
	reg [127:0] state_in;
	wire state_in_sel;
	reg [127:0] add_state_in;
	wire add_state_in_sel;
	wire [127:0] state_mask;
	wire [(((NumShares * 4) * 4) * 8) - 1:0] state_init;
	wire [(((NumShares * 4) * 4) * 8) - 1:0] state_done;
	wire [127:0] state_out;
	reg [511:0] key_init;
	reg [15:0] key_init_qe;
	reg [511:0] key_init_d;
	reg [511:0] key_init_q;
	wire [((NumShares * 8) * 32) - 1:0] key_init_cipher;
	wire [15:0] key_init_we;
	wire key_init_sel;
	reg [127:0] iv;
	reg [3:0] iv_qe;
	reg [127:0] iv_d;
	reg [127:0] iv_q;
	wire [7:0] iv_we;
	wire [2:0] iv_sel;
	wire [127:0] ctr;
	wire [7:0] ctr_we;
	wire ctr_incr;
	wire ctr_ready;
	reg [127:0] data_in_prev_d;
	reg [127:0] data_in_prev_q;
	wire data_in_prev_we;
	wire data_in_prev_sel;
	reg [127:0] data_in;
	reg [3:0] data_in_qe;
	wire data_in_we;
	reg [127:0] add_state_out;
	wire [2:0] add_state_out_sel;
	wire [127:0] data_out_d;
	reg [127:0] data_out_q;
	wire data_out_we;
	reg [3:0] data_out_re;
	wire cipher_in_valid;
	wire cipher_in_ready;
	wire cipher_out_valid;
	wire cipher_out_ready;
	wire cipher_crypt;
	wire cipher_crypt_busy;
	wire cipher_dec_key_gen;
	wire cipher_dec_key_gen_busy;
	wire cipher_key_clear;
	wire cipher_key_clear_busy;
	wire cipher_data_out_clear;
	wire cipher_data_out_clear_busy;
	wire [63:0] prd_clearing;
	wire prd_clearing_upd_req;
	wire prd_clearing_upd_ack;
	wire prd_clearing_rsd_req;
	wire prd_clearing_rsd_ack;
	wire [127:0] prd_clearing_128;
	wire [255:0] prd_clearing_256;
	reg [127:0] unused_data_out_q;
	wire unused_force_zero_masks;
	aes_prng_clearing #(
		.Width(aes_pkg_WidthPRDClearing),
		.DefaultSeed(SeedClearing)
	) u_aes_prng_clearing(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.data_req_i(prd_clearing_upd_req),
		.data_ack_o(prd_clearing_upd_ack),
		.data_o(prd_clearing),
		.reseed_req_i(prd_clearing_rsd_req),
		.reseed_ack_o(prd_clearing_rsd_ack),
		.entropy_req_o(entropy_clearing_req_o),
		.entropy_ack_i(entropy_clearing_ack_i),
		.entropy_i(entropy_clearing_i)
	);
	localparam [31:0] NumChunks = 2;
	genvar c;
	generate
		for (c = 0; c < NumChunks; c = c + 1) begin : gen_prd_clearing
			assign prd_clearing_128[c * aes_pkg_WidthPRDClearing+:aes_pkg_WidthPRDClearing] = prd_clearing;
			assign prd_clearing_256[c * aes_pkg_WidthPRDClearing+:aes_pkg_WidthPRDClearing] = prd_clearing;
			assign prd_clearing_256[(c * aes_pkg_WidthPRDClearing) + 128+:aes_pkg_WidthPRDClearing] = prd_clearing;
		end
	endgenerate
	always @(*) begin : key_init_get
		begin : sv2v_autoblock_1
			reg signed [31:0] i;
			for (i = 0; i < 8; i = i + 1)
				begin
					key_init[(8 + i) * 32+:32] = reg2hw[688 + ((i * 33) + 32)-:32];
					key_init_qe[8 + i] = reg2hw[688 + (i * 33)];
					key_init[i * 32+:32] = reg2hw[424 + ((i * 33) + 32)-:32];
					key_init_qe[i] = reg2hw[424 + (i * 33)];
				end
		end
	end
	always @(*) begin : iv_get
		begin : sv2v_autoblock_2
			reg signed [31:0] i;
			for (i = 0; i < 4; i = i + 1)
				begin
					iv[i * 32+:32] = reg2hw[292 + ((i * 33) + 32)-:32];
					iv_qe[i] = reg2hw[292 + (i * 33)];
				end
		end
	end
	always @(*) begin : data_in_get
		begin : sv2v_autoblock_3
			reg signed [31:0] i;
			for (i = 0; i < 4; i = i + 1)
				begin
					data_in[i * 32+:32] = reg2hw[160 + ((i * 33) + 32)-:32];
					data_in_qe[i] = reg2hw[160 + (i * 33)];
				end
		end
	end
	always @(*) begin : data_out_get
		begin : sv2v_autoblock_4
			reg signed [31:0] i;
			for (i = 0; i < 4; i = i + 1)
				begin
					unused_data_out_q[i * 32+:32] = reg2hw[28 + ((i * 33) + 32)-:32];
					data_out_re[i] = reg2hw[28 + (i * 33)];
				end
		end
	end
	always @(*) begin : key_init_mux
		case (key_init_sel)
			1'd0: key_init_d = key_init;
			1'd1: key_init_d = {2 {prd_clearing_256}};
			default: key_init_d = {2 {prd_clearing_256}};
		endcase
	end
	always @(posedge clk_i) begin : key_init_reg
		begin : sv2v_autoblock_5
			reg signed [31:0] s;
			for (s = 0; s < 2; s = s + 1)
				begin : sv2v_autoblock_6
					reg signed [31:0] i;
					for (i = 0; i < 8; i = i + 1)
						if (key_init_we[((1 - s) * 8) + i])
							key_init_q[(((1 - s) * 8) + i) * 32+:32] <= key_init_d[(((1 - s) * 8) + i) * 32+:32];
				end
		end
	end
	function automatic [127:0] aes_pkg_aes_transpose;
		input reg [127:0] in;
		reg [127:0] transpose;
		begin
			transpose = 1'sb0;
			begin : sv2v_autoblock_7
				reg signed [31:0] j;
				for (j = 0; j < 4; j = j + 1)
					begin : sv2v_autoblock_8
						reg signed [31:0] i;
						for (i = 0; i < 4; i = i + 1)
							transpose[((i * 4) + j) * 8+:8] = in[((j * 4) + i) * 8+:8];
					end
			end
			aes_pkg_aes_transpose = transpose;
		end
	endfunction
	always @(*) begin : iv_mux
		case (iv_sel)
			3'd0: iv_d = iv;
			3'd1: iv_d = data_out_d;
			3'd2: iv_d = aes_pkg_aes_transpose(state_out);
			3'd3: iv_d = data_in_prev_q;
			3'd4: iv_d = ctr;
			3'd5: iv_d = prd_clearing_128;
			default: iv_d = prd_clearing_128;
		endcase
	end
	always @(posedge clk_i) begin : iv_reg
		begin : sv2v_autoblock_9
			reg signed [31:0] i;
			for (i = 0; i < 8; i = i + 1)
				if (iv_we[i])
					iv_q[i * 16+:16] <= iv_d[i * 16+:16];
		end
	end
	always @(*) begin : data_in_prev_mux
		case (data_in_prev_sel)
			1'd0: data_in_prev_d = data_in;
			1'd1: data_in_prev_d = prd_clearing_128;
			default: data_in_prev_d = prd_clearing_128;
		endcase
	end
	always @(posedge clk_i) begin : data_in_prev_reg
		if (data_in_prev_we)
			data_in_prev_q <= data_in_prev_d;
	end
	aes_ctr u_aes_ctr(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.incr_i(ctr_incr),
		.ready_o(ctr_ready),
		.ctr_i(iv_q),
		.ctr_o(ctr),
		.ctr_we_o(ctr_we)
	);
	assign cipher_op = ((aes_mode_q == 6'b000001) && (aes_op_q == 1'b0) ? 1'b0 : ((aes_mode_q == 6'b000001) && (aes_op_q == 1'b1) ? 1'b1 : ((aes_mode_q == 6'b000010) && (aes_op_q == 1'b0) ? 1'b0 : ((aes_mode_q == 6'b000010) && (aes_op_q == 1'b1) ? 1'b1 : (aes_mode_q == 6'b000100 ? 1'b0 : (aes_mode_q == 6'b001000 ? 1'b0 : (aes_mode_q == 6'b010000 ? 1'b0 : 1'b0)))))));
	always @(*) begin : state_in_mux
		case (state_in_sel)
			1'd0: state_in = 1'sb0;
			1'd1: state_in = aes_pkg_aes_transpose(data_in);
			default: state_in = 1'sb0;
		endcase
	end
	always @(*) begin : add_state_in_mux
		case (add_state_in_sel)
			1'd0: add_state_in = 1'sb0;
			1'd1: add_state_in = aes_pkg_aes_transpose(iv_q);
			default: add_state_in = 1'sb0;
		endcase
	end
	generate
		if (!Masking) begin : gen_state_init_unmasked
			assign state_init[8 * (4 * ((NumShares - 1) * 4))+:128] = state_in ^ add_state_in;
			wire [127:0] unused_state_mask;
			assign unused_state_mask = state_mask;
		end
		else begin : gen_state_init_masked
			assign state_init[8 * (4 * ((NumShares - 1) * 4))+:128] = (state_in ^ add_state_in) ^ state_mask;
			assign state_init[8 * (4 * ((NumShares - 2) * 4))+:128] = state_mask;
		end
		if (!Masking) begin : gen_key_init_unmasked
			assign key_init_cipher[32 * ((NumShares - 1) * 8)+:256] = key_init_q[256+:256] ^ key_init_q[0+:256];
		end
		else begin : gen_key_init_masked
			assign key_init_cipher = key_init_q;
		end
	endgenerate
	aes_cipher_core #(
		.AES192Enable(AES192Enable),
		.Masking(Masking),
		.SBoxImpl(SBoxImpl),
		.SecAllowForcingMasks(SecAllowForcingMasks),
		.SeedMasking(SeedMasking)
	) u_aes_cipher_core(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.in_valid_i(cipher_in_valid),
		.in_ready_o(cipher_in_ready),
		.out_valid_o(cipher_out_valid),
		.out_ready_i(cipher_out_ready),
		.cfg_valid_i(~ctrl_err_storage_o),
		.op_i(cipher_op),
		.key_len_i(key_len_q),
		.crypt_i(cipher_crypt),
		.crypt_o(cipher_crypt_busy),
		.dec_key_gen_i(cipher_dec_key_gen),
		.dec_key_gen_o(cipher_dec_key_gen_busy),
		.key_clear_i(cipher_key_clear),
		.key_clear_o(cipher_key_clear_busy),
		.data_out_clear_i(cipher_data_out_clear),
		.data_out_clear_o(cipher_data_out_clear_busy),
		.prd_clearing_i(prd_clearing),
		.force_zero_masks_i(force_zero_masks_q),
		.data_in_mask_o(state_mask),
		.entropy_req_o(entropy_masking_req_o),
		.entropy_ack_i(entropy_masking_ack_i),
		.entropy_i(entropy_masking_i),
		.state_init_i(state_init),
		.key_init_i(key_init_cipher),
		.state_o(state_done)
	);
	generate
		if (!Masking) begin : gen_state_out_unmasked
			assign state_out = state_done[8 * (4 * ((NumShares - 1) * 4))+:128];
		end
		else begin : gen_state_out_masked
			assign state_out = state_done[8 * (4 * ((NumShares - 1) * 4))+:128] ^ state_done[8 * (4 * ((NumShares - 2) * 4))+:128];
		end
	endgenerate
	always @(*) begin : add_state_out_mux
		case (add_state_out_sel)
			3'd0: add_state_out = 1'sb0;
			3'd1: add_state_out = aes_pkg_aes_transpose(iv_q);
			3'd2: add_state_out = aes_pkg_aes_transpose(data_in_prev_q);
			default: add_state_out = 1'sb0;
		endcase
	end
	assign data_out_d = aes_pkg_aes_transpose(state_out ^ add_state_out);
	wire [1:1] sv2v_tmp_6E92D;
	assign sv2v_tmp_6E92D = reg2hw[27];
	always @(*) ctrl_d[0] = sv2v_tmp_6E92D;
	function automatic [5:0] sv2v_cast_6;
		input reg [5:0] inp;
		sv2v_cast_6 = inp;
	endfunction
	assign mode = sv2v_cast_6(reg2hw[24-:6]);
	always @(*) begin : mode_get
		case (mode)
			6'b000001: ctrl_d[6-:6] = 6'b000001;
			6'b000010: ctrl_d[6-:6] = 6'b000010;
			6'b000100: ctrl_d[6-:6] = 6'b000100;
			6'b001000: ctrl_d[6-:6] = 6'b001000;
			6'b010000: ctrl_d[6-:6] = 6'b010000;
			default: ctrl_d[6-:6] = 6'b100000;
		endcase
	end
	function automatic [2:0] sv2v_cast_3;
		input reg [2:0] inp;
		sv2v_cast_3 = inp;
	endfunction
	assign key_len = sv2v_cast_3(reg2hw[16-:3]);
	always @(*) begin : key_len_get
		case (key_len)
			3'b001: ctrl_d[9-:3] = 3'b001;
			3'b100: ctrl_d[9-:3] = 3'b100;
			3'b010: ctrl_d[9-:3] = (AES192Enable ? 3'b010 : 3'b100);
			default: ctrl_d[9-:3] = 3'b100;
		endcase
	end
	wire [1:1] sv2v_tmp_61D0D;
	assign sv2v_tmp_61D0D = reg2hw[11];
	always @(*) ctrl_d[10] = sv2v_tmp_61D0D;
	wire [1:1] sv2v_tmp_B36BF;
	assign sv2v_tmp_B36BF = (SecAllowForcingMasks ? reg2hw[8] : 1'b0);
	always @(*) ctrl_d[11] = sv2v_tmp_B36BF;
	assign unused_force_zero_masks = (SecAllowForcingMasks ? 1'b0 : reg2hw[8]);
	assign ctrl_re = (((reg2hw[25] & reg2hw[17]) & reg2hw[12]) & reg2hw[9]) & reg2hw[6];
	assign ctrl_qe = (((reg2hw[26] & reg2hw[18]) & reg2hw[13]) & reg2hw[10]) & reg2hw[7];
	localparam [11:0] aes_pkg_CTRL_RESET = 12'b000011000000;
	prim_subreg_shadow #(
		.DW(12),
		.SWACCESS("WO"),
		.RESVAL(aes_pkg_CTRL_RESET)
	) u_ctrl_reg_shadowed(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.re(ctrl_re),
		.we(ctrl_we),
		.wd(ctrl_d),
		.de(1'b0),
		.d(1'sb0),
		.qe(),
		.q(ctrl_q),
		.qs(),
		.err_update(ctrl_err_update_o),
		.err_storage(ctrl_err_storage_o)
	);
	wire [1:1] sv2v_tmp_915AA;
	assign sv2v_tmp_915AA = ctrl_err_storage_o;
	always @(*) hw2reg[1] = sv2v_tmp_915AA;
	wire [1:1] sv2v_tmp_FD89F;
	assign sv2v_tmp_FD89F = ctrl_err_storage_o;
	always @(*) hw2reg[0] = sv2v_tmp_FD89F;
	assign aes_op_q = ctrl_q[0];
	assign aes_mode_q = ctrl_q[6-:6];
	assign key_len_q = ctrl_q[9-:3];
	assign manual_operation_q = ctrl_q[10];
	assign force_zero_masks_q = ctrl_q[11];
	wire unused_alert_signals;
	assign unused_alert_signals = ^reg2hw[955-:4];
	wire [1:1] sv2v_tmp_u_aes_control_start_o;
	always @(*) hw2reg[21] = sv2v_tmp_u_aes_control_start_o;
	wire [1:1] sv2v_tmp_u_aes_control_start_we_o;
	always @(*) hw2reg[20] = sv2v_tmp_u_aes_control_start_we_o;
	wire [1:1] sv2v_tmp_u_aes_control_key_clear_o;
	always @(*) hw2reg[19] = sv2v_tmp_u_aes_control_key_clear_o;
	wire [1:1] sv2v_tmp_u_aes_control_key_clear_we_o;
	always @(*) hw2reg[18] = sv2v_tmp_u_aes_control_key_clear_we_o;
	wire [1:1] sv2v_tmp_u_aes_control_iv_clear_o;
	always @(*) hw2reg[17] = sv2v_tmp_u_aes_control_iv_clear_o;
	wire [1:1] sv2v_tmp_u_aes_control_iv_clear_we_o;
	always @(*) hw2reg[16] = sv2v_tmp_u_aes_control_iv_clear_we_o;
	wire [1:1] sv2v_tmp_u_aes_control_data_in_clear_o;
	always @(*) hw2reg[15] = sv2v_tmp_u_aes_control_data_in_clear_o;
	wire [1:1] sv2v_tmp_u_aes_control_data_in_clear_we_o;
	always @(*) hw2reg[14] = sv2v_tmp_u_aes_control_data_in_clear_we_o;
	wire [1:1] sv2v_tmp_u_aes_control_data_out_clear_o;
	always @(*) hw2reg[13] = sv2v_tmp_u_aes_control_data_out_clear_o;
	wire [1:1] sv2v_tmp_u_aes_control_data_out_clear_we_o;
	always @(*) hw2reg[12] = sv2v_tmp_u_aes_control_data_out_clear_we_o;
	wire [1:1] sv2v_tmp_u_aes_control_prng_reseed_o;
	always @(*) hw2reg[11] = sv2v_tmp_u_aes_control_prng_reseed_o;
	wire [1:1] sv2v_tmp_u_aes_control_prng_reseed_we_o;
	always @(*) hw2reg[10] = sv2v_tmp_u_aes_control_prng_reseed_we_o;
	wire [1:1] sv2v_tmp_u_aes_control_output_valid_o;
	always @(*) hw2reg[5] = sv2v_tmp_u_aes_control_output_valid_o;
	wire [1:1] sv2v_tmp_u_aes_control_output_valid_we_o;
	always @(*) hw2reg[4] = sv2v_tmp_u_aes_control_output_valid_we_o;
	wire [1:1] sv2v_tmp_u_aes_control_input_ready_o;
	always @(*) hw2reg[3] = sv2v_tmp_u_aes_control_input_ready_o;
	wire [1:1] sv2v_tmp_u_aes_control_input_ready_we_o;
	always @(*) hw2reg[2] = sv2v_tmp_u_aes_control_input_ready_we_o;
	wire [1:1] sv2v_tmp_u_aes_control_idle_o;
	always @(*) hw2reg[9] = sv2v_tmp_u_aes_control_idle_o;
	wire [1:1] sv2v_tmp_u_aes_control_idle_we_o;
	always @(*) hw2reg[8] = sv2v_tmp_u_aes_control_idle_we_o;
	wire [1:1] sv2v_tmp_u_aes_control_stall_o;
	always @(*) hw2reg[7] = sv2v_tmp_u_aes_control_stall_o;
	wire [1:1] sv2v_tmp_u_aes_control_stall_we_o;
	always @(*) hw2reg[6] = sv2v_tmp_u_aes_control_stall_we_o;
	aes_control #(.SecStartTriggerDelay(SecStartTriggerDelay)) u_aes_control(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.ctrl_qe_i(ctrl_qe),
		.ctrl_we_o(ctrl_we),
		.ctrl_err_storage_i(ctrl_err_storage_o),
		.op_i(aes_op_q),
		.mode_i(aes_mode_q),
		.cipher_op_i(cipher_op),
		.manual_operation_i(manual_operation_q),
		.start_i(reg2hw[5]),
		.key_clear_i(reg2hw[4]),
		.iv_clear_i(reg2hw[3]),
		.data_in_clear_i(reg2hw[2]),
		.data_out_clear_i(reg2hw[1]),
		.prng_reseed_i(reg2hw[-0]),
		.key_init_qe_i(key_init_qe),
		.iv_qe_i(iv_qe),
		.data_in_qe_i(data_in_qe),
		.data_out_re_i(data_out_re),
		.data_in_we_o(data_in_we),
		.data_out_we_o(data_out_we),
		.data_in_prev_sel_o(data_in_prev_sel),
		.data_in_prev_we_o(data_in_prev_we),
		.state_in_sel_o(state_in_sel),
		.add_state_in_sel_o(add_state_in_sel),
		.add_state_out_sel_o(add_state_out_sel),
		.ctr_incr_o(ctr_incr),
		.ctr_ready_i(ctr_ready),
		.ctr_we_i(ctr_we),
		.cipher_in_valid_o(cipher_in_valid),
		.cipher_in_ready_i(cipher_in_ready),
		.cipher_out_valid_i(cipher_out_valid),
		.cipher_out_ready_o(cipher_out_ready),
		.cipher_crypt_o(cipher_crypt),
		.cipher_crypt_i(cipher_crypt_busy),
		.cipher_dec_key_gen_o(cipher_dec_key_gen),
		.cipher_dec_key_gen_i(cipher_dec_key_gen_busy),
		.cipher_key_clear_o(cipher_key_clear),
		.cipher_key_clear_i(cipher_key_clear_busy),
		.cipher_data_out_clear_o(cipher_data_out_clear),
		.cipher_data_out_clear_i(cipher_data_out_clear_busy),
		.key_init_sel_o(key_init_sel),
		.key_init_we_o(key_init_we),
		.iv_sel_o(iv_sel),
		.iv_we_o(iv_we),
		.prng_data_req_o(prd_clearing_upd_req),
		.prng_data_ack_i(prd_clearing_upd_ack),
		.prng_reseed_req_o(prd_clearing_rsd_req),
		.prng_reseed_ack_i(prd_clearing_rsd_ack),
		.start_o(sv2v_tmp_u_aes_control_start_o),
		.start_we_o(sv2v_tmp_u_aes_control_start_we_o),
		.key_clear_o(sv2v_tmp_u_aes_control_key_clear_o),
		.key_clear_we_o(sv2v_tmp_u_aes_control_key_clear_we_o),
		.iv_clear_o(sv2v_tmp_u_aes_control_iv_clear_o),
		.iv_clear_we_o(sv2v_tmp_u_aes_control_iv_clear_we_o),
		.data_in_clear_o(sv2v_tmp_u_aes_control_data_in_clear_o),
		.data_in_clear_we_o(sv2v_tmp_u_aes_control_data_in_clear_we_o),
		.data_out_clear_o(sv2v_tmp_u_aes_control_data_out_clear_o),
		.data_out_clear_we_o(sv2v_tmp_u_aes_control_data_out_clear_we_o),
		.prng_reseed_o(sv2v_tmp_u_aes_control_prng_reseed_o),
		.prng_reseed_we_o(sv2v_tmp_u_aes_control_prng_reseed_we_o),
		.output_valid_o(sv2v_tmp_u_aes_control_output_valid_o),
		.output_valid_we_o(sv2v_tmp_u_aes_control_output_valid_we_o),
		.input_ready_o(sv2v_tmp_u_aes_control_input_ready_o),
		.input_ready_we_o(sv2v_tmp_u_aes_control_input_ready_we_o),
		.idle_o(sv2v_tmp_u_aes_control_idle_o),
		.idle_we_o(sv2v_tmp_u_aes_control_idle_we_o),
		.stall_o(sv2v_tmp_u_aes_control_stall_o),
		.stall_we_o(sv2v_tmp_u_aes_control_stall_we_o)
	);
	always @(*) begin : data_in_reg_clear
		begin : sv2v_autoblock_10
			reg signed [31:0] i;
			for (i = 0; i < 4; i = i + 1)
				begin
					hw2reg[162 + ((i * 33) + 32)-:32] = 1'sb0;
					hw2reg[162 + (i * 33)] = data_in_we;
				end
		end
	end
	always @(posedge clk_i) begin : data_out_reg
		if (data_out_we)
			data_out_q <= data_out_d;
	end
	always @(*) begin : key_reg_put
		begin : sv2v_autoblock_11
			reg signed [31:0] i;
			for (i = 0; i < 8; i = i + 1)
				begin
					hw2reg[678 + ((i * 32) + 31)-:32] = key_init_q[(8 + i) * 32+:32];
					hw2reg[422 + ((i * 32) + 31)-:32] = key_init_q[i * 32+:32];
				end
		end
	end
	always @(*) begin : iv_reg_put
		begin : sv2v_autoblock_12
			reg signed [31:0] i;
			for (i = 0; i < 4; i = i + 1)
				hw2reg[294 + ((i * 32) + 31)-:32] = {iv_q[((2 * i) + 1) * 16+:16], iv_q[(2 * i) * 16+:16]};
		end
	end
	always @(*) begin : data_out_put
		begin : sv2v_autoblock_13
			reg signed [31:0] i;
			for (i = 0; i < 4; i = i + 1)
				hw2reg[34 + ((i * 32) + 31)-:32] = data_out_q[i * 32+:32];
		end
	end
	wire [6:1] sv2v_tmp_4F169;
	assign sv2v_tmp_4F169 = {aes_mode_q};
	always @(*) hw2reg[32-:6] = sv2v_tmp_4F169;
	wire [3:1] sv2v_tmp_F60AE;
	assign sv2v_tmp_F60AE = {key_len_q};
	always @(*) hw2reg[26-:3] = sv2v_tmp_F60AE;
	wire [1:1] sv2v_tmp_EB7D8;
	assign sv2v_tmp_EB7D8 = {aes_op_q};
	always @(*) hw2reg[33] = sv2v_tmp_EB7D8;
	wire [1:1] sv2v_tmp_68A2C;
	assign sv2v_tmp_68A2C = manual_operation_q;
	always @(*) hw2reg[23] = sv2v_tmp_68A2C;
	wire [1:1] sv2v_tmp_D07F9;
	assign sv2v_tmp_D07F9 = force_zero_masks_q;
	always @(*) hw2reg[22] = sv2v_tmp_D07F9;
endmodule
module aes_ctr (
	clk_i,
	rst_ni,
	incr_i,
	ready_o,
	ctr_i,
	ctr_o,
	ctr_we_o
);
	input wire clk_i;
	input wire rst_ni;
	input wire incr_i;
	output reg ready_o;
	input wire [127:0] ctr_i;
	output wire [127:0] ctr_o;
	output wire [7:0] ctr_we_o;
	function automatic [127:0] aes_rev_order_byte;
		input reg [127:0] in;
		reg [127:0] out;
		begin
			begin : sv2v_autoblock_1
				reg signed [31:0] i;
				for (i = 0; i < 16; i = i + 1)
					out[i * 8+:8] = in[(15 - i) * 8+:8];
			end
			aes_rev_order_byte = out;
		end
	endfunction
	function automatic [7:0] aes_rev_order_bit;
		input reg [7:0] in;
		reg [7:0] out;
		begin
			begin : sv2v_autoblock_2
				reg signed [31:0] i;
				for (i = 0; i < 8; i = i + 1)
					out[i] = in[7 - i];
			end
			aes_rev_order_bit = out;
		end
	endfunction
	reg aes_ctr_ns;
	reg aes_ctr_cs;
	reg [2:0] ctr_slice_idx_d;
	reg [2:0] ctr_slice_idx_q;
	reg ctr_carry_d;
	reg ctr_carry_q;
	wire [127:0] ctr_i_rev;
	reg [127:0] ctr_o_rev;
	reg [7:0] ctr_we_o_rev;
	reg ctr_we;
	wire [15:0] ctr_i_slice;
	wire [15:0] ctr_o_slice;
	wire [16:0] ctr_value;
	assign ctr_i_rev = aes_rev_order_byte(ctr_i);
	assign ctr_i_slice = ctr_i_rev[ctr_slice_idx_q * 16+:16];
	assign ctr_value = ctr_i_slice + {15'b000000000000000, ctr_carry_q};
	assign ctr_o_slice = ctr_value[15:0];
	always @(*) begin : aes_ctr_fsm
		ready_o = 1'b0;
		ctr_we = 1'b0;
		aes_ctr_ns = aes_ctr_cs;
		ctr_slice_idx_d = ctr_slice_idx_q;
		ctr_carry_d = ctr_carry_q;
		case (aes_ctr_cs)
			1'd0: begin
				ready_o = 1'b1;
				if (incr_i) begin
					ctr_slice_idx_d = 1'sb0;
					ctr_carry_d = 1'b1;
					aes_ctr_ns = 1'd1;
				end
			end
			1'd1: begin
				ctr_slice_idx_d = ctr_slice_idx_q + 3'b001;
				ctr_carry_d = ctr_value[16];
				ctr_we = 1'b1;
				if (ctr_slice_idx_q == 3'b111)
					aes_ctr_ns = 1'd0;
			end
			default: aes_ctr_ns = 1'd0;
		endcase
	end
	always @(posedge clk_i or negedge rst_ni)
		if (!rst_ni) begin
			aes_ctr_cs <= 1'd0;
			ctr_slice_idx_q <= 1'sb0;
			ctr_carry_q <= 1'sb0;
		end
		else begin
			aes_ctr_cs <= aes_ctr_ns;
			ctr_slice_idx_q <= ctr_slice_idx_d;
			ctr_carry_q <= ctr_carry_d;
		end
	always @(*) begin
		ctr_o_rev = ctr_i_rev;
		ctr_o_rev[ctr_slice_idx_q * 16+:16] = ctr_o_slice;
	end
	always @(*) begin
		ctr_we_o_rev = 1'sb0;
		ctr_we_o_rev[ctr_slice_idx_q] = ctr_we;
	end
	assign ctr_o = aes_rev_order_byte(ctr_o_rev);
	assign ctr_we_o = aes_rev_order_bit(ctr_we_o_rev);
endmodule
module aes_key_expand (
	clk_i,
	rst_ni,
	cfg_valid_i,
	op_i,
	step_i,
	clear_i,
	round_i,
	key_len_i,
	key_i,
	key_o,
	prd_masking_i
);
	parameter [0:0] AES192Enable = 1;
	parameter [0:0] Masking = 0;
	parameter integer SBoxImpl = 32'sd0;
	localparam signed [31:0] NumShares = (Masking ? 2 : 1);
	input wire clk_i;
	input wire rst_ni;
	input wire cfg_valid_i;
	input wire op_i;
	input wire step_i;
	input wire clear_i;
	input wire [3:0] round_i;
	input wire [2:0] key_len_i;
	input wire [((NumShares * 8) * 32) - 1:0] key_i;
	output wire [((NumShares * 8) * 32) - 1:0] key_o;
	localparam [31:0] aes_pkg_WidthPRDKey = 32;
	input wire [31:0] prd_masking_i;
	reg [7:0] rcon_d;
	reg [7:0] rcon_q;
	wire rcon_we;
	reg use_rcon;
	wire [3:0] rnd;
	reg [3:0] rnd_type;
	wire [31:0] spec_in_128 [0:NumShares - 1];
	wire [31:0] spec_in_192 [0:NumShares - 1];
	reg [31:0] rot_word_in [0:NumShares - 1];
	wire [31:0] rot_word_out [0:NumShares - 1];
	wire use_rot_word;
	wire [31:0] sub_word_in;
	wire [31:0] sub_word_out;
	wire [31:0] sw_in_mask;
	wire [31:0] sw_out_mask;
	wire [7:0] rcon_add_in;
	wire [7:0] rcon_add_out;
	wire [31:0] rcon_added;
	wire [31:0] irregular [0:NumShares - 1];
	reg [((NumShares * 8) * 32) - 1:0] regular;
	wire unused_cfg_valid;
	assign unused_cfg_valid = cfg_valid_i;
	assign rnd = round_i;
	always @(*) begin : get_rnd_type
		if (AES192Enable) begin
			rnd_type[0] = rnd == 0;
			rnd_type[1] = (((rnd == 1) || (rnd == 4)) || (rnd == 7)) || (rnd == 10);
			rnd_type[2] = (((rnd == 2) || (rnd == 5)) || (rnd == 8)) || (rnd == 11);
			rnd_type[3] = (((rnd == 3) || (rnd == 6)) || (rnd == 9)) || (rnd == 12);
		end
		else
			rnd_type = 1'sb0;
	end
	assign use_rot_word = ((key_len_i == 3'b100) && (rnd[0] == 1'b0) ? 1'b0 : 1'b1);
	always @(*) begin : rcon_usage
		use_rcon = 1'b1;
		if (AES192Enable)
			if ((key_len_i == 3'b010) && (((op_i == 1'b0) && rnd_type[1]) || ((op_i == 1'b1) && (rnd_type[0] || rnd_type[3]))))
				use_rcon = 1'b0;
		if ((key_len_i == 3'b100) && (rnd[0] == 1'b0))
			use_rcon = 1'b0;
	end
	function automatic [7:0] aes_pkg_aes_div2;
		input reg [7:0] in;
		reg [7:0] out;
		begin
			out[7] = in[0];
			out[6] = in[7];
			out[5] = in[6];
			out[4] = in[5];
			out[3] = in[4] ^ in[0];
			out[2] = in[3] ^ in[0];
			out[1] = in[2];
			out[0] = in[1] ^ in[0];
			aes_pkg_aes_div2 = out;
		end
	endfunction
	function automatic [7:0] aes_pkg_aes_mul2;
		input reg [7:0] in;
		reg [7:0] out;
		begin
			out[7] = in[6];
			out[6] = in[5];
			out[5] = in[4];
			out[4] = in[3] ^ in[7];
			out[3] = in[2] ^ in[7];
			out[2] = in[1];
			out[1] = in[0] ^ in[7];
			out[0] = in[7];
			aes_pkg_aes_mul2 = out;
		end
	endfunction
	always @(*) begin : rcon_update
		rcon_d = rcon_q;
		if (clear_i)
			rcon_d = (op_i == 1'b0 ? 8'h01 : ((op_i == 1'b1) && (key_len_i == 3'b001) ? 8'h36 : ((op_i == 1'b1) && (key_len_i == 3'b010) ? 8'h80 : ((op_i == 1'b1) && (key_len_i == 3'b100) ? 8'h40 : 8'h01))));
		else
			rcon_d = (op_i == 1'b0 ? aes_pkg_aes_mul2(rcon_q) : (op_i == 1'b1 ? aes_pkg_aes_div2(rcon_q) : 8'h01));
	end
	assign rcon_we = clear_i | (step_i & use_rcon);
	always @(posedge clk_i or negedge rst_ni) begin : reg_rcon
		if (!rst_ni)
			rcon_q <= 1'sb0;
		else if (rcon_we)
			rcon_q <= rcon_d;
	end
	genvar s;
	function automatic [31:0] aes_pkg_aes_circ_byte_shift;
		input reg [31:0] in;
		input reg [1:0] shift;
		reg [31:0] out;
		reg [31:0] s;
		begin
			s = {30'b000000000000000000000000000000, shift};
			out = {in[8 * ((7 - s) % 4)+:8], in[8 * ((6 - s) % 4)+:8], in[8 * ((5 - s) % 4)+:8], in[8 * ((4 - s) % 4)+:8]};
			aes_pkg_aes_circ_byte_shift = out;
		end
	endfunction
	generate
		for (s = 0; s < NumShares; s = s + 1) begin : gen_shares_rot_word_out
			assign spec_in_128[s] = key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + 2) * 32+:32];
			assign spec_in_192[s] = (AES192Enable ? (key_i[((((NumShares - 1) - s) * 8) + 5) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + 1) * 32+:32]) ^ key_i[(((NumShares - 1) - s) * 8) * 32+:32] : {32 {1'sb0}});
			always @(*) begin : rot_word_in_mux
				case (key_len_i)
					3'b001:
						case (op_i)
							1'b0: rot_word_in[s] = key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32];
							1'b1: rot_word_in[s] = spec_in_128[s];
							default: rot_word_in[s] = key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32];
						endcase
					3'b010:
						if (AES192Enable)
							case (op_i)
								1'b0: rot_word_in[s] = (rnd_type[0] ? key_i[((((NumShares - 1) - s) * 8) + 5) * 32+:32] : (rnd_type[2] ? key_i[((((NumShares - 1) - s) * 8) + 5) * 32+:32] : (rnd_type[3] ? spec_in_192[s] : key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32])));
								1'b1: rot_word_in[s] = (rnd_type[1] ? key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32] : (rnd_type[2] ? key_i[((((NumShares - 1) - s) * 8) + 1) * 32+:32] : key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32]));
								default: rot_word_in[s] = key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32];
							endcase
						else
							rot_word_in[s] = key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32];
					3'b100:
						case (op_i)
							1'b0: rot_word_in[s] = key_i[((((NumShares - 1) - s) * 8) + 7) * 32+:32];
							1'b1: rot_word_in[s] = key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32];
							default: rot_word_in[s] = key_i[((((NumShares - 1) - s) * 8) + 7) * 32+:32];
						endcase
					default: rot_word_in[s] = key_i[((((NumShares - 1) - s) * 8) + 3) * 32+:32];
				endcase
			end
			assign rot_word_out[s] = aes_pkg_aes_circ_byte_shift(rot_word_in[s], 2'h3);
		end
	endgenerate
	assign sub_word_in = (use_rot_word ? rot_word_out[0] : rot_word_in[0]);
	generate
		if (!Masking) begin : gen_no_sw_in_mask
			assign sw_in_mask = 1'sb0;
		end
		else begin : gen_sw_in_mask
			assign sw_in_mask = (use_rot_word ? rot_word_out[1] : rot_word_in[1]);
		end
	endgenerate
	assign sw_out_mask = prd_masking_i;
	genvar i;
	generate
		for (i = 0; i < 4; i = i + 1) begin : gen_sbox
			aes_sbox #(.SBoxImpl(SBoxImpl)) u_aes_sbox_i(
				.op_i(1'b0),
				.data_i(sub_word_in[8 * i+:8]),
				.in_mask_i(sw_in_mask[8 * i+:8]),
				.out_mask_i(sw_out_mask[8 * i+:8]),
				.data_o(sub_word_out[8 * i+:8])
			);
		end
	endgenerate
	assign rcon_add_in = sub_word_out[7:0];
	assign rcon_add_out = rcon_add_in ^ rcon_q;
	assign rcon_added = {sub_word_out[31:8], rcon_add_out};
	generate
		for (s = 0; s < NumShares; s = s + 1) begin : gen_shares_irregular
			if (s == 0) begin : gen_irregular_rcon
				assign irregular[s] = (use_rcon ? rcon_added : sub_word_out);
			end
			else begin : gen_irregular_no_rcon
				assign irregular[s] = sw_out_mask;
			end
		end
		for (s = 0; s < NumShares; s = s + 1) begin : gen_shares_regular
			always @(*) begin : drive_regular
				case (key_len_i)
					3'b001: begin
						regular[32 * ((((NumShares - 1) - s) * 8) + 4)+:128] = key_i[32 * (((NumShares - 1) - s) * 8)+:128];
						regular[(((NumShares - 1) - s) * 8) * 32+:32] = irregular[s] ^ key_i[(((NumShares - 1) - s) * 8) * 32+:32];
						case (op_i)
							1'b0: begin : sv2v_autoblock_1
								reg signed [31:0] i;
								for (i = 1; i < 4; i = i + 1)
									regular[((((NumShares - 1) - s) * 8) + i) * 32+:32] = regular[((((NumShares - 1) - s) * 8) + (i - 1)) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + i) * 32+:32];
							end
							1'b1: begin : sv2v_autoblock_2
								reg signed [31:0] i;
								for (i = 1; i < 4; i = i + 1)
									regular[((((NumShares - 1) - s) * 8) + i) * 32+:32] = key_i[((((NumShares - 1) - s) * 8) + (i - 1)) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + i) * 32+:32];
							end
							default: regular[32 * (((NumShares - 1) - s) * 8)+:256] = {key_i[32 * (((NumShares - 1) - s) * 8)+:128], key_i[32 * ((((NumShares - 1) - s) * 8) + 4)+:128]};
						endcase
					end
					3'b010: begin
						regular[32 * ((((NumShares - 1) - s) * 8) + 6)+:64] = key_i[32 * ((((NumShares - 1) - s) * 8) + 2)+:64];
						if (AES192Enable)
							case (op_i)
								1'b0:
									if (rnd_type[0]) begin
										regular[32 * (((NumShares - 1) - s) * 8)+:128] = key_i[32 * ((((NumShares - 1) - s) * 8) + 2)+:128];
										regular[((((NumShares - 1) - s) * 8) + 4) * 32+:32] = irregular[s] ^ key_i[(((NumShares - 1) - s) * 8) * 32+:32];
										regular[((((NumShares - 1) - s) * 8) + 5) * 32+:32] = regular[((((NumShares - 1) - s) * 8) + 4) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + 1) * 32+:32];
									end
									else begin
										regular[32 * (((NumShares - 1) - s) * 8)+:64] = key_i[32 * ((((NumShares - 1) - s) * 8) + 4)+:64];
										begin : sv2v_autoblock_3
											reg signed [31:0] i;
											for (i = 0; i < 4; i = i + 1)
												if (((i == 0) && rnd_type[2]) || ((i == 2) && rnd_type[3]))
													regular[((((NumShares - 1) - s) * 8) + (i + 2)) * 32+:32] = irregular[s] ^ key_i[((((NumShares - 1) - s) * 8) + i) * 32+:32];
												else
													regular[((((NumShares - 1) - s) * 8) + (i + 2)) * 32+:32] = regular[((((NumShares - 1) - s) * 8) + (i + 1)) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + i) * 32+:32];
										end
									end
								1'b1:
									if (rnd_type[0]) begin
										regular[32 * ((((NumShares - 1) - s) * 8) + 2)+:128] = key_i[32 * (((NumShares - 1) - s) * 8)+:128];
										begin : sv2v_autoblock_4
											reg signed [31:0] i;
											for (i = 0; i < 2; i = i + 1)
												regular[((((NumShares - 1) - s) * 8) + i) * 32+:32] = key_i[((((NumShares - 1) - s) * 8) + (3 + i)) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + ((3 + i) + 1)) * 32+:32];
										end
									end
									else begin
										regular[32 * ((((NumShares - 1) - s) * 8) + 4)+:64] = key_i[32 * (((NumShares - 1) - s) * 8)+:64];
										begin : sv2v_autoblock_5
											reg signed [31:0] i;
											for (i = 0; i < 4; i = i + 1)
												if (((i == 2) && rnd_type[1]) || ((i == 0) && rnd_type[2]))
													regular[((((NumShares - 1) - s) * 8) + i) * 32+:32] = irregular[s] ^ key_i[((((NumShares - 1) - s) * 8) + (i + 2)) * 32+:32];
												else
													regular[((((NumShares - 1) - s) * 8) + i) * 32+:32] = key_i[((((NumShares - 1) - s) * 8) + (i + 1)) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + (i + 2)) * 32+:32];
										end
									end
								default: regular[32 * (((NumShares - 1) - s) * 8)+:256] = {key_i[32 * (((NumShares - 1) - s) * 8)+:128], key_i[32 * ((((NumShares - 1) - s) * 8) + 4)+:128]};
							endcase
						else
							regular[32 * (((NumShares - 1) - s) * 8)+:256] = {key_i[32 * (((NumShares - 1) - s) * 8)+:128], key_i[32 * ((((NumShares - 1) - s) * 8) + 4)+:128]};
					end
					3'b100:
						case (op_i)
							1'b0:
								if (rnd == 0)
									regular[32 * (((NumShares - 1) - s) * 8)+:256] = {key_i[32 * (((NumShares - 1) - s) * 8)+:128], key_i[32 * ((((NumShares - 1) - s) * 8) + 4)+:128]};
								else begin
									regular[32 * (((NumShares - 1) - s) * 8)+:128] = key_i[32 * ((((NumShares - 1) - s) * 8) + 4)+:128];
									regular[((((NumShares - 1) - s) * 8) + 4) * 32+:32] = irregular[s] ^ key_i[(((NumShares - 1) - s) * 8) * 32+:32];
									begin : sv2v_autoblock_6
										reg signed [31:0] i;
										for (i = 1; i < 4; i = i + 1)
											regular[((((NumShares - 1) - s) * 8) + (i + 4)) * 32+:32] = regular[((((NumShares - 1) - s) * 8) + (i + 3)) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + i) * 32+:32];
									end
								end
							1'b1:
								if (rnd == 0)
									regular[32 * (((NumShares - 1) - s) * 8)+:256] = {key_i[32 * (((NumShares - 1) - s) * 8)+:128], key_i[32 * ((((NumShares - 1) - s) * 8) + 4)+:128]};
								else begin
									regular[32 * ((((NumShares - 1) - s) * 8) + 4)+:128] = key_i[32 * (((NumShares - 1) - s) * 8)+:128];
									regular[(((NumShares - 1) - s) * 8) * 32+:32] = irregular[s] ^ key_i[((((NumShares - 1) - s) * 8) + 4) * 32+:32];
									begin : sv2v_autoblock_7
										reg signed [31:0] i;
										for (i = 0; i < 3; i = i + 1)
											regular[((((NumShares - 1) - s) * 8) + (i + 1)) * 32+:32] = key_i[((((NumShares - 1) - s) * 8) + (4 + i)) * 32+:32] ^ key_i[((((NumShares - 1) - s) * 8) + ((4 + i) + 1)) * 32+:32];
									end
								end
							default: regular[32 * (((NumShares - 1) - s) * 8)+:256] = {key_i[32 * (((NumShares - 1) - s) * 8)+:128], key_i[32 * ((((NumShares - 1) - s) * 8) + 4)+:128]};
						endcase
					default: regular[32 * (((NumShares - 1) - s) * 8)+:256] = {key_i[32 * (((NumShares - 1) - s) * 8)+:128], key_i[32 * ((((NumShares - 1) - s) * 8) + 4)+:128]};
				endcase
			end
		end
	endgenerate
	assign key_o = regular;
	initial begin : AesMaskedCoreAndSBox
		
	end
endmodule
module aes_mix_columns (
	op_i,
	data_i,
	data_o
);
	input wire op_i;
	input wire [127:0] data_i;
	output wire [127:0] data_o;
	wire [127:0] data_i_transposed;
	wire [127:0] data_o_transposed;
	function automatic [127:0] aes_pkg_aes_transpose;
		input reg [127:0] in;
		reg [127:0] transpose;
		begin
			transpose = 1'sb0;
			begin : sv2v_autoblock_1
				reg signed [31:0] j;
				for (j = 0; j < 4; j = j + 1)
					begin : sv2v_autoblock_2
						reg signed [31:0] i;
						for (i = 0; i < 4; i = i + 1)
							transpose[((i * 4) + j) * 8+:8] = in[((j * 4) + i) * 8+:8];
					end
			end
			aes_pkg_aes_transpose = transpose;
		end
	endfunction
	assign data_i_transposed = aes_pkg_aes_transpose(data_i);
	genvar i;
	generate
		for (i = 0; i < 4; i = i + 1) begin : gen_mix_column
			aes_mix_single_column u_aes_mix_column_i(
				.op_i(op_i),
				.data_i(data_i_transposed[8 * (i * 4)+:32]),
				.data_o(data_o_transposed[8 * (i * 4)+:32])
			);
		end
	endgenerate
	assign data_o = aes_pkg_aes_transpose(data_o_transposed);
endmodule
module aes_mix_single_column (
	op_i,
	data_i,
	data_o
);
	input wire op_i;
	input wire [31:0] data_i;
	output wire [31:0] data_o;
	wire [31:0] x;
	wire [15:0] y;
	wire [15:0] z;
	wire [31:0] x_mul2;
	wire [15:0] y_pre_mul4;
	wire [7:0] y2;
	wire [7:0] y2_pre_mul2;
	wire [15:0] z_muxed;
	assign x[0+:8] = data_i[0+:8] ^ data_i[24+:8];
	assign x[8+:8] = data_i[24+:8] ^ data_i[16+:8];
	assign x[16+:8] = data_i[16+:8] ^ data_i[8+:8];
	assign x[24+:8] = data_i[8+:8] ^ data_i[0+:8];
	genvar i;
	function automatic [7:0] aes_pkg_aes_mul2;
		input reg [7:0] in;
		reg [7:0] out;
		begin
			out[7] = in[6];
			out[6] = in[5];
			out[5] = in[4];
			out[4] = in[3] ^ in[7];
			out[3] = in[2] ^ in[7];
			out[2] = in[1];
			out[1] = in[0] ^ in[7];
			out[0] = in[7];
			aes_pkg_aes_mul2 = out;
		end
	endfunction
	generate
		for (i = 0; i < 4; i = i + 1) begin : gen_x_mul2
			assign x_mul2[i * 8+:8] = aes_pkg_aes_mul2(x[i * 8+:8]);
		end
	endgenerate
	assign y_pre_mul4[0+:8] = data_i[24+:8] ^ data_i[8+:8];
	assign y_pre_mul4[8+:8] = data_i[16+:8] ^ data_i[0+:8];
	function automatic [7:0] aes_pkg_aes_mul4;
		input reg [7:0] in;
		aes_pkg_aes_mul4 = aes_pkg_aes_mul2(aes_pkg_aes_mul2(in));
	endfunction
	generate
		for (i = 0; i < 2; i = i + 1) begin : gen_mul4
			assign y[i * 8+:8] = aes_pkg_aes_mul4(y_pre_mul4[i * 8+:8]);
		end
	endgenerate
	assign y2_pre_mul2 = y[0+:8] ^ y[8+:8];
	assign y2 = aes_pkg_aes_mul2(y2_pre_mul2);
	assign z[0+:8] = y2 ^ y[0+:8];
	assign z[8+:8] = y2 ^ y[8+:8];
	assign z_muxed[0+:8] = (op_i == 1'b0 ? 8'b00000000 : z[0+:8]);
	assign z_muxed[8+:8] = (op_i == 1'b0 ? 8'b00000000 : z[8+:8]);
	assign data_o[0+:8] = ((data_i[8+:8] ^ x_mul2[24+:8]) ^ x[8+:8]) ^ z_muxed[8+:8];
	assign data_o[8+:8] = ((data_i[0+:8] ^ x_mul2[16+:8]) ^ x[8+:8]) ^ z_muxed[0+:8];
	assign data_o[16+:8] = ((data_i[24+:8] ^ x_mul2[8+:8]) ^ x[24+:8]) ^ z_muxed[8+:8];
	assign data_o[24+:8] = ((data_i[16+:8] ^ x_mul2[0+:8]) ^ x[24+:8]) ^ z_muxed[0+:8];
endmodule
module aes_prng_clearing (
	clk_i,
	rst_ni,
	data_req_i,
	data_ack_o,
	data_o,
	reseed_req_i,
	reseed_ack_o,
	entropy_req_o,
	entropy_ack_i,
	entropy_i
);
	parameter [31:0] Width = 64;
	function automatic signed [Width - 1:0] sv2v_cast_92C3D_signed;
		input reg signed [Width - 1:0] inp;
		sv2v_cast_92C3D_signed = inp;
	endfunction
	parameter [Width - 1:0] DefaultSeed = {sv2v_cast_92C3D_signed(1)};
	input wire clk_i;
	input wire rst_ni;
	input wire data_req_i;
	output wire data_ack_o;
	output wire [Width - 1:0] data_o;
	input wire reseed_req_i;
	output wire reseed_ack_o;
	output wire entropy_req_o;
	input wire entropy_ack_i;
	input wire [Width - 1:0] entropy_i;
	wire seed_en;
	wire lfsr_en;
	wire [Width - 1:0] lfsr_state;
	wire [Width - 1:0] scrambled;
	assign data_ack_o = (reseed_req_i ? 1'b0 : data_req_i);
	assign reseed_ack_o = entropy_ack_i;
	assign entropy_req_o = reseed_req_i;
	assign lfsr_en = data_req_i & data_ack_o;
	assign seed_en = entropy_req_o & entropy_ack_i;
	prim_lfsr #(
		.LfsrType("GAL_XOR"),
		.LfsrDw(Width),
		.StateOutDw(Width),
		.DefaultSeed(DefaultSeed)
	) u_lfsr(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.seed_en_i(seed_en),
		.seed_i(entropy_i),
		.lfsr_en_i(lfsr_en),
		.entropy_i(1'sb0),
		.state_o(lfsr_state)
	);
	localparam [63:0] prim_cipher_pkg_PRINCE_SBOX4 = 64'h4d5e087619ca23fb;
	function automatic [7:0] prim_cipher_pkg_sbox4_8bit;
		input reg [7:0] state_in;
		input reg [63:0] sbox4;
		reg [7:0] state_out;
		begin
			begin : sv2v_autoblock_1
				reg signed [31:0] k;
				for (k = 0; k < 2; k = k + 1)
					state_out[k * 4+:4] = sbox4[state_in[k * 4+:4] * 4+:4];
			end
			prim_cipher_pkg_sbox4_8bit = state_out;
		end
	endfunction
	function automatic [63:0] prim_cipher_pkg_sbox4_64bit;
		input reg [63:0] state_in;
		input reg [63:0] sbox4;
		reg [63:0] state_out;
		begin
			begin : sv2v_autoblock_2
				reg signed [31:0] k;
				for (k = 0; k < 8; k = k + 1)
					state_out[k * 8+:8] = prim_cipher_pkg_sbox4_8bit(state_in[k * 8+:8], sbox4);
			end
			prim_cipher_pkg_sbox4_64bit = state_out;
		end
	endfunction
	assign scrambled = prim_cipher_pkg_sbox4_64bit(lfsr_state, prim_cipher_pkg_PRINCE_SBOX4);
	localparam [383:0] prim_cipher_pkg_PRESENT_PERM64 = 384'hfef7cffae78ef6d74df2c70ceeb6cbeaa68ae69649e28608de75c7da6586d65545d24504ce34c3ca2482c61441c20400;
	function automatic [63:0] prim_cipher_pkg_perm_64bit;
		input reg [63:0] state_in;
		input reg [383:0] perm;
		reg [63:0] state_out;
		begin
			begin : sv2v_autoblock_3
				reg signed [31:0] k;
				for (k = 0; k < 64; k = k + 1)
					state_out[perm[k * 6+:6]] = state_in[k];
			end
			prim_cipher_pkg_perm_64bit = state_out;
		end
	endfunction
	assign data_o = prim_cipher_pkg_perm_64bit(scrambled, prim_cipher_pkg_PRESENT_PERM64);
	initial begin : AesPrngWidth
		
	end
endmodule
module aes_prng_masking (
	clk_i,
	rst_ni,
	force_zero_masks_i,
	data_update_i,
	data_o,
	reseed_req_i,
	reseed_ack_o,
	entropy_req_o,
	entropy_ack_i,
	entropy_i
);
	parameter [31:0] Width = 160;
	localparam [31:0] CHUNK_SIZE = 32;
	localparam [31:0] NumChunks = Width / CHUNK_SIZE;
	parameter [0:0] SecAllowForcingMasks = 0;
	function automatic signed [31:0] sv2v_cast_7ABF0_signed;
		input reg signed [31:0] inp;
		sv2v_cast_7ABF0_signed = inp;
	endfunction
	parameter [(NumChunks * CHUNK_SIZE) - 1:0] DefaultSeed = {NumChunks {sv2v_cast_7ABF0_signed(1)}};
	input wire clk_i;
	input wire rst_ni;
	input wire force_zero_masks_i;
	input wire data_update_i;
	output wire [Width - 1:0] data_o;
	input wire reseed_req_i;
	output wire reseed_ack_o;
	output wire entropy_req_o;
	input wire entropy_ack_i;
	input wire [Width - 1:0] entropy_i;
	wire seed_en;
	wire [(NumChunks * CHUNK_SIZE) - 1:0] prng_seed;
	wire prng_en;
	wire [(NumChunks * CHUNK_SIZE) - 1:0] prng_state;
	wire [(NumChunks * CHUNK_SIZE) - 1:0] sub;
	wire [(NumChunks * CHUNK_SIZE) - 1:0] perm;
	reg phase_q;
	assign entropy_req_o = reseed_req_i;
	assign reseed_ack_o = entropy_ack_i;
	assign prng_en = data_update_i;
	assign seed_en = 1'b0;
	genvar c;
	localparam [159:0] prim_cipher_pkg_PRESENT_PERM32 = 160'hfdde7f59c6ed5a5e5184dcd63d4942cc521c4100;
	localparam [63:0] prim_cipher_pkg_PRINCE_SBOX4 = 64'h4d5e087619ca23fb;
	function automatic [31:0] prim_cipher_pkg_perm_32bit;
		input reg [31:0] state_in;
		input reg [159:0] perm;
		reg [31:0] state_out;
		begin
			begin : sv2v_autoblock_1
				reg signed [31:0] k;
				for (k = 0; k < 32; k = k + 1)
					state_out[perm[k * 5+:5]] = state_in[k];
			end
			prim_cipher_pkg_perm_32bit = state_out;
		end
	endfunction
	function automatic [7:0] prim_cipher_pkg_sbox4_8bit;
		input reg [7:0] state_in;
		input reg [63:0] sbox4;
		reg [7:0] state_out;
		begin
			begin : sv2v_autoblock_2
				reg signed [31:0] k;
				for (k = 0; k < 2; k = k + 1)
					state_out[k * 4+:4] = sbox4[state_in[k * 4+:4] * 4+:4];
			end
			prim_cipher_pkg_sbox4_8bit = state_out;
		end
	endfunction
	function automatic [31:0] prim_cipher_pkg_sbox4_32bit;
		input reg [31:0] state_in;
		input reg [63:0] sbox4;
		reg [31:0] state_out;
		begin
			begin : sv2v_autoblock_3
				reg signed [31:0] k;
				for (k = 0; k < 4; k = k + 1)
					state_out[k * 8+:8] = prim_cipher_pkg_sbox4_8bit(state_in[k * 8+:8], sbox4);
			end
			prim_cipher_pkg_sbox4_32bit = state_out;
		end
	endfunction
	generate
		for (c = 0; c < NumChunks; c = c + 1) begin : gen_chunks
			assign prng_seed[c * CHUNK_SIZE+:CHUNK_SIZE] = entropy_i[c * CHUNK_SIZE+:CHUNK_SIZE];
			prim_lfsr #(
				.LfsrType("GAL_XOR"),
				.LfsrDw(CHUNK_SIZE),
				.StateOutDw(CHUNK_SIZE),
				.DefaultSeed(DefaultSeed[c * CHUNK_SIZE+:CHUNK_SIZE])
			) u_lfsr_chunk(
				.clk_i(clk_i),
				.rst_ni(rst_ni),
				.seed_en_i(seed_en),
				.seed_i(prng_seed[c * CHUNK_SIZE+:CHUNK_SIZE]),
				.lfsr_en_i(prng_en),
				.entropy_i(1'sb0),
				.state_o(prng_state[c * CHUNK_SIZE+:CHUNK_SIZE])
			);
			assign sub[c * CHUNK_SIZE+:CHUNK_SIZE] = prim_cipher_pkg_sbox4_32bit(prng_state[c * CHUNK_SIZE+:CHUNK_SIZE], prim_cipher_pkg_PRINCE_SBOX4);
			assign perm[c * CHUNK_SIZE+:CHUNK_SIZE] = prim_cipher_pkg_perm_32bit(sub[c * CHUNK_SIZE+:CHUNK_SIZE], prim_cipher_pkg_PRESENT_PERM32);
		end
	endgenerate
	assign data_o = (SecAllowForcingMasks && force_zero_masks_i ? {Width {1'sb0}} : (phase_q ? {perm[0+:CHUNK_SIZE], perm[CHUNK_SIZE * (((NumChunks - 1) >= 1 ? NumChunks - 1 : ((NumChunks - 1) + ((NumChunks - 1) >= 1 ? NumChunks - 1 : 3 - NumChunks)) - 1) - (((NumChunks - 1) >= 1 ? NumChunks - 1 : 3 - NumChunks) - 1))+:CHUNK_SIZE * ((NumChunks - 1) >= 1 ? NumChunks - 1 : 3 - NumChunks)]} : perm));
	generate
		if (!SecAllowForcingMasks) begin : gen_unused_force_masks
			wire unused_force_zero_masks;
			assign unused_force_zero_masks = force_zero_masks_i;
		end
	endgenerate
	always @(posedge clk_i or negedge rst_ni) begin : reg_phase
		if (!rst_ni)
			phase_q <= 1'sb0;
		else if (prng_en)
			phase_q <= ~phase_q;
	end
	initial begin : AesPrngMaskingWidth
		
	end
endmodule
module aes_reg_status (
	clk_i,
	rst_ni,
	we_i,
	use_i,
	clear_i,
	arm_i,
	new_o,
	clean_o
);
	parameter signed [31:0] Width = 1;
	input wire clk_i;
	input wire rst_ni;
	input wire [Width - 1:0] we_i;
	input wire use_i;
	input wire clear_i;
	input wire arm_i;
	output wire new_o;
	output wire clean_o;
	wire [Width - 1:0] we_d;
	reg [Width - 1:0] we_q;
	wire armed_d;
	reg armed_q;
	wire all_written;
	wire none_written;
	wire new_d;
	reg new_q;
	wire clean_d;
	reg clean_q;
	assign we_d = (clear_i || use_i ? {Width {1'sb0}} : (armed_q && |we_i ? we_i : we_q | we_i));
	assign armed_d = (clear_i || use_i ? 1'b0 : (armed_q && |we_i ? 1'b0 : armed_q | arm_i));
	always @(posedge clk_i or negedge rst_ni) begin : reg_ops
		if (!rst_ni) begin
			we_q <= 1'sb0;
			armed_q <= 1'b0;
		end
		else begin
			we_q <= we_d;
			armed_q <= armed_d;
		end
	end
	assign all_written = &we_d;
	assign none_written = ~|we_d;
	assign new_d = (clear_i || use_i ? 1'b0 : all_written);
	assign clean_d = (clear_i ? 1'b0 : (all_written ? 1'b1 : (none_written ? clean_q : 1'b0)));
	always @(posedge clk_i or negedge rst_ni) begin : reg_status
		if (!rst_ni) begin
			new_q <= 1'b0;
			clean_q <= 1'b0;
		end
		else begin
			new_q <= new_d;
			clean_q <= clean_d;
		end
	end
	assign new_o = new_q;
	assign clean_o = clean_q;
endmodule
module aes_reg_top (
	clk_i,
	rst_ni,
	tl_i,
	tl_o,
	reg2hw,
	hw2reg,
	devmode_i
);
	input clk_i;
	input rst_ni;
	localparam signed [31:0] top_pkg_TL_AIW = 8;
	localparam signed [31:0] top_pkg_TL_AW = 32;
	localparam signed [31:0] top_pkg_TL_DW = 32;
	localparam signed [31:0] top_pkg_TL_DBW = top_pkg_TL_DW >> 3;
	localparam signed [31:0] top_pkg_TL_SZW = $clog2($clog2(top_pkg_TL_DBW) + 1);
	input wire [(((((7 + top_pkg_TL_SZW) + top_pkg_TL_AIW) + top_pkg_TL_AW) + top_pkg_TL_DBW) + top_pkg_TL_DW) + 16:0] tl_i;
	localparam signed [31:0] top_pkg_TL_DIW = 1;
	localparam signed [31:0] top_pkg_TL_DUW = 16;
	output wire [(((((7 + top_pkg_TL_SZW) + top_pkg_TL_AIW) + top_pkg_TL_DIW) + top_pkg_TL_DW) + top_pkg_TL_DUW) + 1:0] tl_o;
	output wire [955:0] reg2hw;
	input wire [933:0] hw2reg;
	input devmode_i;
	localparam signed [31:0] AW = 7;
	localparam signed [31:0] DW = 32;
	localparam signed [31:0] DBW = 4;
	wire reg_we;
	wire reg_re;
	wire [6:0] reg_addr;
	wire [31:0] reg_wdata;
	wire [3:0] reg_be;
	wire [31:0] reg_rdata;
	wire reg_error;
	wire addrmiss;
	reg wr_err;
	reg [31:0] reg_rdata_next;
	wire [(((((7 + top_pkg_TL_SZW) + top_pkg_TL_AIW) + top_pkg_TL_AW) + top_pkg_TL_DBW) + top_pkg_TL_DW) + 16:0] tl_reg_h2d;
	wire [(((((7 + top_pkg_TL_SZW) + top_pkg_TL_AIW) + top_pkg_TL_DIW) + top_pkg_TL_DW) + top_pkg_TL_DUW) + 1:0] tl_reg_d2h;
	assign tl_reg_h2d = tl_i;
	assign tl_o = tl_reg_d2h;
	tlul_adapter_reg #(
		.RegAw(AW),
		.RegDw(DW)
	) u_reg_if(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.tl_i(tl_reg_h2d),
		.tl_o(tl_reg_d2h),
		.we_o(reg_we),
		.re_o(reg_re),
		.addr_o(reg_addr),
		.wdata_o(reg_wdata),
		.be_o(reg_be),
		.rdata_i(reg_rdata),
		.error_i(reg_error)
	);
	assign reg_rdata = reg_rdata_next;
	assign reg_error = (devmode_i & addrmiss) | wr_err;
	wire alert_test_ctrl_err_update_wd;
	wire alert_test_ctrl_err_update_we;
	wire alert_test_ctrl_err_storage_wd;
	wire alert_test_ctrl_err_storage_we;
	wire [31:0] key_share0_0_wd;
	wire key_share0_0_we;
	wire [31:0] key_share0_1_wd;
	wire key_share0_1_we;
	wire [31:0] key_share0_2_wd;
	wire key_share0_2_we;
	wire [31:0] key_share0_3_wd;
	wire key_share0_3_we;
	wire [31:0] key_share0_4_wd;
	wire key_share0_4_we;
	wire [31:0] key_share0_5_wd;
	wire key_share0_5_we;
	wire [31:0] key_share0_6_wd;
	wire key_share0_6_we;
	wire [31:0] key_share0_7_wd;
	wire key_share0_7_we;
	wire [31:0] key_share1_0_wd;
	wire key_share1_0_we;
	wire [31:0] key_share1_1_wd;
	wire key_share1_1_we;
	wire [31:0] key_share1_2_wd;
	wire key_share1_2_we;
	wire [31:0] key_share1_3_wd;
	wire key_share1_3_we;
	wire [31:0] key_share1_4_wd;
	wire key_share1_4_we;
	wire [31:0] key_share1_5_wd;
	wire key_share1_5_we;
	wire [31:0] key_share1_6_wd;
	wire key_share1_6_we;
	wire [31:0] key_share1_7_wd;
	wire key_share1_7_we;
	wire [31:0] iv_0_wd;
	wire iv_0_we;
	wire [31:0] iv_1_wd;
	wire iv_1_we;
	wire [31:0] iv_2_wd;
	wire iv_2_we;
	wire [31:0] iv_3_wd;
	wire iv_3_we;
	wire [31:0] data_in_0_wd;
	wire data_in_0_we;
	wire [31:0] data_in_1_wd;
	wire data_in_1_we;
	wire [31:0] data_in_2_wd;
	wire data_in_2_we;
	wire [31:0] data_in_3_wd;
	wire data_in_3_we;
	wire [31:0] data_out_0_qs;
	wire data_out_0_re;
	wire [31:0] data_out_1_qs;
	wire data_out_1_re;
	wire [31:0] data_out_2_qs;
	wire data_out_2_re;
	wire [31:0] data_out_3_qs;
	wire data_out_3_re;
	wire ctrl_shadowed_operation_qs;
	wire ctrl_shadowed_operation_wd;
	wire ctrl_shadowed_operation_we;
	wire ctrl_shadowed_operation_re;
	wire [5:0] ctrl_shadowed_mode_qs;
	wire [5:0] ctrl_shadowed_mode_wd;
	wire ctrl_shadowed_mode_we;
	wire ctrl_shadowed_mode_re;
	wire [2:0] ctrl_shadowed_key_len_qs;
	wire [2:0] ctrl_shadowed_key_len_wd;
	wire ctrl_shadowed_key_len_we;
	wire ctrl_shadowed_key_len_re;
	wire ctrl_shadowed_manual_operation_qs;
	wire ctrl_shadowed_manual_operation_wd;
	wire ctrl_shadowed_manual_operation_we;
	wire ctrl_shadowed_manual_operation_re;
	wire ctrl_shadowed_force_zero_masks_qs;
	wire ctrl_shadowed_force_zero_masks_wd;
	wire ctrl_shadowed_force_zero_masks_we;
	wire ctrl_shadowed_force_zero_masks_re;
	wire trigger_start_wd;
	wire trigger_start_we;
	wire trigger_key_clear_wd;
	wire trigger_key_clear_we;
	wire trigger_iv_clear_wd;
	wire trigger_iv_clear_we;
	wire trigger_data_in_clear_wd;
	wire trigger_data_in_clear_we;
	wire trigger_data_out_clear_wd;
	wire trigger_data_out_clear_we;
	wire trigger_prng_reseed_wd;
	wire trigger_prng_reseed_we;
	wire status_idle_qs;
	wire status_stall_qs;
	wire status_output_valid_qs;
	wire status_input_ready_qs;
	wire status_ctrl_err_storage_qs;
	prim_subreg_ext #(.DW(1)) u_alert_test_ctrl_err_update(
		.re(1'b0),
		.we(alert_test_ctrl_err_update_we),
		.wd(alert_test_ctrl_err_update_wd),
		.d(1'sb0),
		.qre(),
		.qe(reg2hw[954]),
		.q(reg2hw[955]),
		.qs()
	);
	prim_subreg_ext #(.DW(1)) u_alert_test_ctrl_err_storage(
		.re(1'b0),
		.we(alert_test_ctrl_err_storage_we),
		.wd(alert_test_ctrl_err_storage_wd),
		.d(1'sb0),
		.qre(),
		.qe(reg2hw[952]),
		.q(reg2hw[953]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share0_0(
		.re(1'b0),
		.we(key_share0_0_we),
		.wd(key_share0_0_wd),
		.d(hw2reg[709-:32]),
		.qre(),
		.qe(reg2hw[688]),
		.q(reg2hw[720-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share0_1(
		.re(1'b0),
		.we(key_share0_1_we),
		.wd(key_share0_1_wd),
		.d(hw2reg[741-:32]),
		.qre(),
		.qe(reg2hw[721]),
		.q(reg2hw[753-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share0_2(
		.re(1'b0),
		.we(key_share0_2_we),
		.wd(key_share0_2_wd),
		.d(hw2reg[773-:32]),
		.qre(),
		.qe(reg2hw[754]),
		.q(reg2hw[786-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share0_3(
		.re(1'b0),
		.we(key_share0_3_we),
		.wd(key_share0_3_wd),
		.d(hw2reg[805-:32]),
		.qre(),
		.qe(reg2hw[787]),
		.q(reg2hw[819-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share0_4(
		.re(1'b0),
		.we(key_share0_4_we),
		.wd(key_share0_4_wd),
		.d(hw2reg[837-:32]),
		.qre(),
		.qe(reg2hw[820]),
		.q(reg2hw[852-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share0_5(
		.re(1'b0),
		.we(key_share0_5_we),
		.wd(key_share0_5_wd),
		.d(hw2reg[869-:32]),
		.qre(),
		.qe(reg2hw[853]),
		.q(reg2hw[885-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share0_6(
		.re(1'b0),
		.we(key_share0_6_we),
		.wd(key_share0_6_wd),
		.d(hw2reg[901-:32]),
		.qre(),
		.qe(reg2hw[886]),
		.q(reg2hw[918-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share0_7(
		.re(1'b0),
		.we(key_share0_7_we),
		.wd(key_share0_7_wd),
		.d(hw2reg[933-:32]),
		.qre(),
		.qe(reg2hw[919]),
		.q(reg2hw[951-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share1_0(
		.re(1'b0),
		.we(key_share1_0_we),
		.wd(key_share1_0_wd),
		.d(hw2reg[453-:32]),
		.qre(),
		.qe(reg2hw[424]),
		.q(reg2hw[456-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share1_1(
		.re(1'b0),
		.we(key_share1_1_we),
		.wd(key_share1_1_wd),
		.d(hw2reg[485-:32]),
		.qre(),
		.qe(reg2hw[457]),
		.q(reg2hw[489-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share1_2(
		.re(1'b0),
		.we(key_share1_2_we),
		.wd(key_share1_2_wd),
		.d(hw2reg[517-:32]),
		.qre(),
		.qe(reg2hw[490]),
		.q(reg2hw[522-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share1_3(
		.re(1'b0),
		.we(key_share1_3_we),
		.wd(key_share1_3_wd),
		.d(hw2reg[549-:32]),
		.qre(),
		.qe(reg2hw[523]),
		.q(reg2hw[555-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share1_4(
		.re(1'b0),
		.we(key_share1_4_we),
		.wd(key_share1_4_wd),
		.d(hw2reg[581-:32]),
		.qre(),
		.qe(reg2hw[556]),
		.q(reg2hw[588-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share1_5(
		.re(1'b0),
		.we(key_share1_5_we),
		.wd(key_share1_5_wd),
		.d(hw2reg[613-:32]),
		.qre(),
		.qe(reg2hw[589]),
		.q(reg2hw[621-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share1_6(
		.re(1'b0),
		.we(key_share1_6_we),
		.wd(key_share1_6_wd),
		.d(hw2reg[645-:32]),
		.qre(),
		.qe(reg2hw[622]),
		.q(reg2hw[654-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_key_share1_7(
		.re(1'b0),
		.we(key_share1_7_we),
		.wd(key_share1_7_wd),
		.d(hw2reg[677-:32]),
		.qre(),
		.qe(reg2hw[655]),
		.q(reg2hw[687-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_iv_0(
		.re(1'b0),
		.we(iv_0_we),
		.wd(iv_0_wd),
		.d(hw2reg[325-:32]),
		.qre(),
		.qe(reg2hw[292]),
		.q(reg2hw[324-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_iv_1(
		.re(1'b0),
		.we(iv_1_we),
		.wd(iv_1_wd),
		.d(hw2reg[357-:32]),
		.qre(),
		.qe(reg2hw[325]),
		.q(reg2hw[357-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_iv_2(
		.re(1'b0),
		.we(iv_2_we),
		.wd(iv_2_wd),
		.d(hw2reg[389-:32]),
		.qre(),
		.qe(reg2hw[358]),
		.q(reg2hw[390-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_iv_3(
		.re(1'b0),
		.we(iv_3_we),
		.wd(iv_3_wd),
		.d(hw2reg[421-:32]),
		.qre(),
		.qe(reg2hw[391]),
		.q(reg2hw[423-:32]),
		.qs()
	);
	prim_subreg #(
		.DW(32),
		.SWACCESS("WO"),
		.RESVAL(32'h00000000)
	) u_data_in_0(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(data_in_0_we),
		.wd(data_in_0_wd),
		.de(hw2reg[162]),
		.d(hw2reg[194-:32]),
		.qe(reg2hw[160]),
		.q(reg2hw[192-:32]),
		.qs()
	);
	prim_subreg #(
		.DW(32),
		.SWACCESS("WO"),
		.RESVAL(32'h00000000)
	) u_data_in_1(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(data_in_1_we),
		.wd(data_in_1_wd),
		.de(hw2reg[195]),
		.d(hw2reg[227-:32]),
		.qe(reg2hw[193]),
		.q(reg2hw[225-:32]),
		.qs()
	);
	prim_subreg #(
		.DW(32),
		.SWACCESS("WO"),
		.RESVAL(32'h00000000)
	) u_data_in_2(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(data_in_2_we),
		.wd(data_in_2_wd),
		.de(hw2reg[228]),
		.d(hw2reg[260-:32]),
		.qe(reg2hw[226]),
		.q(reg2hw[258-:32]),
		.qs()
	);
	prim_subreg #(
		.DW(32),
		.SWACCESS("WO"),
		.RESVAL(32'h00000000)
	) u_data_in_3(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(data_in_3_we),
		.wd(data_in_3_wd),
		.de(hw2reg[261]),
		.d(hw2reg[293-:32]),
		.qe(reg2hw[259]),
		.q(reg2hw[291-:32]),
		.qs()
	);
	prim_subreg_ext #(.DW(32)) u_data_out_0(
		.re(data_out_0_re),
		.we(1'b0),
		.wd(1'sb0),
		.d(hw2reg[65-:32]),
		.qre(reg2hw[28]),
		.qe(),
		.q(reg2hw[60-:32]),
		.qs(data_out_0_qs)
	);
	prim_subreg_ext #(.DW(32)) u_data_out_1(
		.re(data_out_1_re),
		.we(1'b0),
		.wd(1'sb0),
		.d(hw2reg[97-:32]),
		.qre(reg2hw[61]),
		.qe(),
		.q(reg2hw[93-:32]),
		.qs(data_out_1_qs)
	);
	prim_subreg_ext #(.DW(32)) u_data_out_2(
		.re(data_out_2_re),
		.we(1'b0),
		.wd(1'sb0),
		.d(hw2reg[129-:32]),
		.qre(reg2hw[94]),
		.qe(),
		.q(reg2hw[126-:32]),
		.qs(data_out_2_qs)
	);
	prim_subreg_ext #(.DW(32)) u_data_out_3(
		.re(data_out_3_re),
		.we(1'b0),
		.wd(1'sb0),
		.d(hw2reg[161-:32]),
		.qre(reg2hw[127]),
		.qe(),
		.q(reg2hw[159-:32]),
		.qs(data_out_3_qs)
	);
	prim_subreg_ext #(.DW(1)) u_ctrl_shadowed_operation(
		.re(ctrl_shadowed_operation_re),
		.we(ctrl_shadowed_operation_we),
		.wd(ctrl_shadowed_operation_wd),
		.d(hw2reg[33]),
		.qre(reg2hw[25]),
		.qe(reg2hw[26]),
		.q(reg2hw[27]),
		.qs(ctrl_shadowed_operation_qs)
	);
	prim_subreg_ext #(.DW(6)) u_ctrl_shadowed_mode(
		.re(ctrl_shadowed_mode_re),
		.we(ctrl_shadowed_mode_we),
		.wd(ctrl_shadowed_mode_wd),
		.d(hw2reg[32-:6]),
		.qre(reg2hw[17]),
		.qe(reg2hw[18]),
		.q(reg2hw[24-:6]),
		.qs(ctrl_shadowed_mode_qs)
	);
	prim_subreg_ext #(.DW(3)) u_ctrl_shadowed_key_len(
		.re(ctrl_shadowed_key_len_re),
		.we(ctrl_shadowed_key_len_we),
		.wd(ctrl_shadowed_key_len_wd),
		.d(hw2reg[26-:3]),
		.qre(reg2hw[12]),
		.qe(reg2hw[13]),
		.q(reg2hw[16-:3]),
		.qs(ctrl_shadowed_key_len_qs)
	);
	prim_subreg_ext #(.DW(1)) u_ctrl_shadowed_manual_operation(
		.re(ctrl_shadowed_manual_operation_re),
		.we(ctrl_shadowed_manual_operation_we),
		.wd(ctrl_shadowed_manual_operation_wd),
		.d(hw2reg[23]),
		.qre(reg2hw[9]),
		.qe(reg2hw[10]),
		.q(reg2hw[11]),
		.qs(ctrl_shadowed_manual_operation_qs)
	);
	prim_subreg_ext #(.DW(1)) u_ctrl_shadowed_force_zero_masks(
		.re(ctrl_shadowed_force_zero_masks_re),
		.we(ctrl_shadowed_force_zero_masks_we),
		.wd(ctrl_shadowed_force_zero_masks_wd),
		.d(hw2reg[22]),
		.qre(reg2hw[6]),
		.qe(reg2hw[7]),
		.q(reg2hw[8]),
		.qs(ctrl_shadowed_force_zero_masks_qs)
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("WO"),
		.RESVAL(1'h0)
	) u_trigger_start(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(trigger_start_we),
		.wd(trigger_start_wd),
		.de(hw2reg[20]),
		.d(hw2reg[21]),
		.qe(),
		.q(reg2hw[5]),
		.qs()
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("WO"),
		.RESVAL(1'h1)
	) u_trigger_key_clear(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(trigger_key_clear_we),
		.wd(trigger_key_clear_wd),
		.de(hw2reg[18]),
		.d(hw2reg[19]),
		.qe(),
		.q(reg2hw[4]),
		.qs()
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("WO"),
		.RESVAL(1'h1)
	) u_trigger_iv_clear(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(trigger_iv_clear_we),
		.wd(trigger_iv_clear_wd),
		.de(hw2reg[16]),
		.d(hw2reg[17]),
		.qe(),
		.q(reg2hw[3]),
		.qs()
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("WO"),
		.RESVAL(1'h1)
	) u_trigger_data_in_clear(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(trigger_data_in_clear_we),
		.wd(trigger_data_in_clear_wd),
		.de(hw2reg[14]),
		.d(hw2reg[15]),
		.qe(),
		.q(reg2hw[2]),
		.qs()
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("WO"),
		.RESVAL(1'h1)
	) u_trigger_data_out_clear(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(trigger_data_out_clear_we),
		.wd(trigger_data_out_clear_wd),
		.de(hw2reg[12]),
		.d(hw2reg[13]),
		.qe(),
		.q(reg2hw[1]),
		.qs()
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("WO"),
		.RESVAL(1'h1)
	) u_trigger_prng_reseed(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(trigger_prng_reseed_we),
		.wd(trigger_prng_reseed_wd),
		.de(hw2reg[10]),
		.d(hw2reg[11]),
		.qe(),
		.q(reg2hw[-0]),
		.qs()
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("RO"),
		.RESVAL(1'h1)
	) u_status_idle(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(1'b0),
		.wd(1'sb0),
		.de(hw2reg[8]),
		.d(hw2reg[9]),
		.qe(),
		.q(),
		.qs(status_idle_qs)
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("RO"),
		.RESVAL(1'h0)
	) u_status_stall(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(1'b0),
		.wd(1'sb0),
		.de(hw2reg[6]),
		.d(hw2reg[7]),
		.qe(),
		.q(),
		.qs(status_stall_qs)
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("RO"),
		.RESVAL(1'h0)
	) u_status_output_valid(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(1'b0),
		.wd(1'sb0),
		.de(hw2reg[4]),
		.d(hw2reg[5]),
		.qe(),
		.q(),
		.qs(status_output_valid_qs)
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("RO"),
		.RESVAL(1'h1)
	) u_status_input_ready(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(1'b0),
		.wd(1'sb0),
		.de(hw2reg[2]),
		.d(hw2reg[3]),
		.qe(),
		.q(),
		.qs(status_input_ready_qs)
	);
	prim_subreg #(
		.DW(1),
		.SWACCESS("RO"),
		.RESVAL(1'h0)
	) u_status_ctrl_err_storage(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.we(1'b0),
		.wd(1'sb0),
		.de(hw2reg[0]),
		.d(hw2reg[1]),
		.qe(),
		.q(),
		.qs(status_ctrl_err_storage_qs)
	);
	reg [31:0] addr_hit;
	localparam [6:0] aes_reg_pkg_AES_ALERT_TEST_OFFSET = 7'h00;
	localparam [6:0] aes_reg_pkg_AES_CTRL_SHADOWED_OFFSET = 7'h74;
	localparam [6:0] aes_reg_pkg_AES_DATA_IN_0_OFFSET = 7'h54;
	localparam [6:0] aes_reg_pkg_AES_DATA_IN_1_OFFSET = 7'h58;
	localparam [6:0] aes_reg_pkg_AES_DATA_IN_2_OFFSET = 7'h5c;
	localparam [6:0] aes_reg_pkg_AES_DATA_IN_3_OFFSET = 7'h60;
	localparam [6:0] aes_reg_pkg_AES_DATA_OUT_0_OFFSET = 7'h64;
	localparam [6:0] aes_reg_pkg_AES_DATA_OUT_1_OFFSET = 7'h68;
	localparam [6:0] aes_reg_pkg_AES_DATA_OUT_2_OFFSET = 7'h6c;
	localparam [6:0] aes_reg_pkg_AES_DATA_OUT_3_OFFSET = 7'h70;
	localparam [6:0] aes_reg_pkg_AES_IV_0_OFFSET = 7'h44;
	localparam [6:0] aes_reg_pkg_AES_IV_1_OFFSET = 7'h48;
	localparam [6:0] aes_reg_pkg_AES_IV_2_OFFSET = 7'h4c;
	localparam [6:0] aes_reg_pkg_AES_IV_3_OFFSET = 7'h50;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE0_0_OFFSET = 7'h04;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE0_1_OFFSET = 7'h08;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE0_2_OFFSET = 7'h0c;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE0_3_OFFSET = 7'h10;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE0_4_OFFSET = 7'h14;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE0_5_OFFSET = 7'h18;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE0_6_OFFSET = 7'h1c;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE0_7_OFFSET = 7'h20;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE1_0_OFFSET = 7'h24;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE1_1_OFFSET = 7'h28;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE1_2_OFFSET = 7'h2c;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE1_3_OFFSET = 7'h30;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE1_4_OFFSET = 7'h34;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE1_5_OFFSET = 7'h38;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE1_6_OFFSET = 7'h3c;
	localparam [6:0] aes_reg_pkg_AES_KEY_SHARE1_7_OFFSET = 7'h40;
	localparam [6:0] aes_reg_pkg_AES_STATUS_OFFSET = 7'h7c;
	localparam [6:0] aes_reg_pkg_AES_TRIGGER_OFFSET = 7'h78;
	always @(*) begin
		addr_hit = 1'sb0;
		addr_hit[0] = reg_addr == aes_reg_pkg_AES_ALERT_TEST_OFFSET;
		addr_hit[1] = reg_addr == aes_reg_pkg_AES_KEY_SHARE0_0_OFFSET;
		addr_hit[2] = reg_addr == aes_reg_pkg_AES_KEY_SHARE0_1_OFFSET;
		addr_hit[3] = reg_addr == aes_reg_pkg_AES_KEY_SHARE0_2_OFFSET;
		addr_hit[4] = reg_addr == aes_reg_pkg_AES_KEY_SHARE0_3_OFFSET;
		addr_hit[5] = reg_addr == aes_reg_pkg_AES_KEY_SHARE0_4_OFFSET;
		addr_hit[6] = reg_addr == aes_reg_pkg_AES_KEY_SHARE0_5_OFFSET;
		addr_hit[7] = reg_addr == aes_reg_pkg_AES_KEY_SHARE0_6_OFFSET;
		addr_hit[8] = reg_addr == aes_reg_pkg_AES_KEY_SHARE0_7_OFFSET;
		addr_hit[9] = reg_addr == aes_reg_pkg_AES_KEY_SHARE1_0_OFFSET;
		addr_hit[10] = reg_addr == aes_reg_pkg_AES_KEY_SHARE1_1_OFFSET;
		addr_hit[11] = reg_addr == aes_reg_pkg_AES_KEY_SHARE1_2_OFFSET;
		addr_hit[12] = reg_addr == aes_reg_pkg_AES_KEY_SHARE1_3_OFFSET;
		addr_hit[13] = reg_addr == aes_reg_pkg_AES_KEY_SHARE1_4_OFFSET;
		addr_hit[14] = reg_addr == aes_reg_pkg_AES_KEY_SHARE1_5_OFFSET;
		addr_hit[15] = reg_addr == aes_reg_pkg_AES_KEY_SHARE1_6_OFFSET;
		addr_hit[16] = reg_addr == aes_reg_pkg_AES_KEY_SHARE1_7_OFFSET;
		addr_hit[17] = reg_addr == aes_reg_pkg_AES_IV_0_OFFSET;
		addr_hit[18] = reg_addr == aes_reg_pkg_AES_IV_1_OFFSET;
		addr_hit[19] = reg_addr == aes_reg_pkg_AES_IV_2_OFFSET;
		addr_hit[20] = reg_addr == aes_reg_pkg_AES_IV_3_OFFSET;
		addr_hit[21] = reg_addr == aes_reg_pkg_AES_DATA_IN_0_OFFSET;
		addr_hit[22] = reg_addr == aes_reg_pkg_AES_DATA_IN_1_OFFSET;
		addr_hit[23] = reg_addr == aes_reg_pkg_AES_DATA_IN_2_OFFSET;
		addr_hit[24] = reg_addr == aes_reg_pkg_AES_DATA_IN_3_OFFSET;
		addr_hit[25] = reg_addr == aes_reg_pkg_AES_DATA_OUT_0_OFFSET;
		addr_hit[26] = reg_addr == aes_reg_pkg_AES_DATA_OUT_1_OFFSET;
		addr_hit[27] = reg_addr == aes_reg_pkg_AES_DATA_OUT_2_OFFSET;
		addr_hit[28] = reg_addr == aes_reg_pkg_AES_DATA_OUT_3_OFFSET;
		addr_hit[29] = reg_addr == aes_reg_pkg_AES_CTRL_SHADOWED_OFFSET;
		addr_hit[30] = reg_addr == aes_reg_pkg_AES_TRIGGER_OFFSET;
		addr_hit[31] = reg_addr == aes_reg_pkg_AES_STATUS_OFFSET;
	end
	assign addrmiss = (reg_re || reg_we ? ~|addr_hit : 1'b0);
	localparam [127:0] aes_reg_pkg_AES_PERMIT = 128'b00011111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111001100010001;
	always @(*) begin
		wr_err = 1'b0;
		if ((addr_hit[0] && reg_we) && (aes_reg_pkg_AES_PERMIT[124+:4] != (aes_reg_pkg_AES_PERMIT[124+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[1] && reg_we) && (aes_reg_pkg_AES_PERMIT[120+:4] != (aes_reg_pkg_AES_PERMIT[120+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[2] && reg_we) && (aes_reg_pkg_AES_PERMIT[116+:4] != (aes_reg_pkg_AES_PERMIT[116+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[3] && reg_we) && (aes_reg_pkg_AES_PERMIT[112+:4] != (aes_reg_pkg_AES_PERMIT[112+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[4] && reg_we) && (aes_reg_pkg_AES_PERMIT[108+:4] != (aes_reg_pkg_AES_PERMIT[108+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[5] && reg_we) && (aes_reg_pkg_AES_PERMIT[104+:4] != (aes_reg_pkg_AES_PERMIT[104+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[6] && reg_we) && (aes_reg_pkg_AES_PERMIT[100+:4] != (aes_reg_pkg_AES_PERMIT[100+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[7] && reg_we) && (aes_reg_pkg_AES_PERMIT[96+:4] != (aes_reg_pkg_AES_PERMIT[96+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[8] && reg_we) && (aes_reg_pkg_AES_PERMIT[92+:4] != (aes_reg_pkg_AES_PERMIT[92+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[9] && reg_we) && (aes_reg_pkg_AES_PERMIT[88+:4] != (aes_reg_pkg_AES_PERMIT[88+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[10] && reg_we) && (aes_reg_pkg_AES_PERMIT[84+:4] != (aes_reg_pkg_AES_PERMIT[84+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[11] && reg_we) && (aes_reg_pkg_AES_PERMIT[80+:4] != (aes_reg_pkg_AES_PERMIT[80+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[12] && reg_we) && (aes_reg_pkg_AES_PERMIT[76+:4] != (aes_reg_pkg_AES_PERMIT[76+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[13] && reg_we) && (aes_reg_pkg_AES_PERMIT[72+:4] != (aes_reg_pkg_AES_PERMIT[72+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[14] && reg_we) && (aes_reg_pkg_AES_PERMIT[68+:4] != (aes_reg_pkg_AES_PERMIT[68+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[15] && reg_we) && (aes_reg_pkg_AES_PERMIT[64+:4] != (aes_reg_pkg_AES_PERMIT[64+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[16] && reg_we) && (aes_reg_pkg_AES_PERMIT[60+:4] != (aes_reg_pkg_AES_PERMIT[60+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[17] && reg_we) && (aes_reg_pkg_AES_PERMIT[56+:4] != (aes_reg_pkg_AES_PERMIT[56+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[18] && reg_we) && (aes_reg_pkg_AES_PERMIT[52+:4] != (aes_reg_pkg_AES_PERMIT[52+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[19] && reg_we) && (aes_reg_pkg_AES_PERMIT[48+:4] != (aes_reg_pkg_AES_PERMIT[48+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[20] && reg_we) && (aes_reg_pkg_AES_PERMIT[44+:4] != (aes_reg_pkg_AES_PERMIT[44+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[21] && reg_we) && (aes_reg_pkg_AES_PERMIT[40+:4] != (aes_reg_pkg_AES_PERMIT[40+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[22] && reg_we) && (aes_reg_pkg_AES_PERMIT[36+:4] != (aes_reg_pkg_AES_PERMIT[36+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[23] && reg_we) && (aes_reg_pkg_AES_PERMIT[32+:4] != (aes_reg_pkg_AES_PERMIT[32+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[24] && reg_we) && (aes_reg_pkg_AES_PERMIT[28+:4] != (aes_reg_pkg_AES_PERMIT[28+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[25] && reg_we) && (aes_reg_pkg_AES_PERMIT[24+:4] != (aes_reg_pkg_AES_PERMIT[24+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[26] && reg_we) && (aes_reg_pkg_AES_PERMIT[20+:4] != (aes_reg_pkg_AES_PERMIT[20+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[27] && reg_we) && (aes_reg_pkg_AES_PERMIT[16+:4] != (aes_reg_pkg_AES_PERMIT[16+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[28] && reg_we) && (aes_reg_pkg_AES_PERMIT[12+:4] != (aes_reg_pkg_AES_PERMIT[12+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[29] && reg_we) && (aes_reg_pkg_AES_PERMIT[8+:4] != (aes_reg_pkg_AES_PERMIT[8+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[30] && reg_we) && (aes_reg_pkg_AES_PERMIT[4+:4] != (aes_reg_pkg_AES_PERMIT[4+:4] & reg_be)))
			wr_err = 1'b1;
		if ((addr_hit[31] && reg_we) && (aes_reg_pkg_AES_PERMIT[0+:4] != (aes_reg_pkg_AES_PERMIT[0+:4] & reg_be)))
			wr_err = 1'b1;
	end
	assign alert_test_ctrl_err_update_we = (addr_hit[0] & reg_we) & ~wr_err;
	assign alert_test_ctrl_err_update_wd = reg_wdata[0];
	assign alert_test_ctrl_err_storage_we = (addr_hit[0] & reg_we) & ~wr_err;
	assign alert_test_ctrl_err_storage_wd = reg_wdata[1];
	assign key_share0_0_we = (addr_hit[1] & reg_we) & ~wr_err;
	assign key_share0_0_wd = reg_wdata[31:0];
	assign key_share0_1_we = (addr_hit[2] & reg_we) & ~wr_err;
	assign key_share0_1_wd = reg_wdata[31:0];
	assign key_share0_2_we = (addr_hit[3] & reg_we) & ~wr_err;
	assign key_share0_2_wd = reg_wdata[31:0];
	assign key_share0_3_we = (addr_hit[4] & reg_we) & ~wr_err;
	assign key_share0_3_wd = reg_wdata[31:0];
	assign key_share0_4_we = (addr_hit[5] & reg_we) & ~wr_err;
	assign key_share0_4_wd = reg_wdata[31:0];
	assign key_share0_5_we = (addr_hit[6] & reg_we) & ~wr_err;
	assign key_share0_5_wd = reg_wdata[31:0];
	assign key_share0_6_we = (addr_hit[7] & reg_we) & ~wr_err;
	assign key_share0_6_wd = reg_wdata[31:0];
	assign key_share0_7_we = (addr_hit[8] & reg_we) & ~wr_err;
	assign key_share0_7_wd = reg_wdata[31:0];
	assign key_share1_0_we = (addr_hit[9] & reg_we) & ~wr_err;
	assign key_share1_0_wd = reg_wdata[31:0];
	assign key_share1_1_we = (addr_hit[10] & reg_we) & ~wr_err;
	assign key_share1_1_wd = reg_wdata[31:0];
	assign key_share1_2_we = (addr_hit[11] & reg_we) & ~wr_err;
	assign key_share1_2_wd = reg_wdata[31:0];
	assign key_share1_3_we = (addr_hit[12] & reg_we) & ~wr_err;
	assign key_share1_3_wd = reg_wdata[31:0];
	assign key_share1_4_we = (addr_hit[13] & reg_we) & ~wr_err;
	assign key_share1_4_wd = reg_wdata[31:0];
	assign key_share1_5_we = (addr_hit[14] & reg_we) & ~wr_err;
	assign key_share1_5_wd = reg_wdata[31:0];
	assign key_share1_6_we = (addr_hit[15] & reg_we) & ~wr_err;
	assign key_share1_6_wd = reg_wdata[31:0];
	assign key_share1_7_we = (addr_hit[16] & reg_we) & ~wr_err;
	assign key_share1_7_wd = reg_wdata[31:0];
	assign iv_0_we = (addr_hit[17] & reg_we) & ~wr_err;
	assign iv_0_wd = reg_wdata[31:0];
	assign iv_1_we = (addr_hit[18] & reg_we) & ~wr_err;
	assign iv_1_wd = reg_wdata[31:0];
	assign iv_2_we = (addr_hit[19] & reg_we) & ~wr_err;
	assign iv_2_wd = reg_wdata[31:0];
	assign iv_3_we = (addr_hit[20] & reg_we) & ~wr_err;
	assign iv_3_wd = reg_wdata[31:0];
	assign data_in_0_we = (addr_hit[21] & reg_we) & ~wr_err;
	assign data_in_0_wd = reg_wdata[31:0];
	assign data_in_1_we = (addr_hit[22] & reg_we) & ~wr_err;
	assign data_in_1_wd = reg_wdata[31:0];
	assign data_in_2_we = (addr_hit[23] & reg_we) & ~wr_err;
	assign data_in_2_wd = reg_wdata[31:0];
	assign data_in_3_we = (addr_hit[24] & reg_we) & ~wr_err;
	assign data_in_3_wd = reg_wdata[31:0];
	assign data_out_0_re = addr_hit[25] && reg_re;
	assign data_out_1_re = addr_hit[26] && reg_re;
	assign data_out_2_re = addr_hit[27] && reg_re;
	assign data_out_3_re = addr_hit[28] && reg_re;
	assign ctrl_shadowed_operation_we = (addr_hit[29] & reg_we) & ~wr_err;
	assign ctrl_shadowed_operation_wd = reg_wdata[0];
	assign ctrl_shadowed_operation_re = addr_hit[29] && reg_re;
	assign ctrl_shadowed_mode_we = (addr_hit[29] & reg_we) & ~wr_err;
	assign ctrl_shadowed_mode_wd = reg_wdata[6:1];
	assign ctrl_shadowed_mode_re = addr_hit[29] && reg_re;
	assign ctrl_shadowed_key_len_we = (addr_hit[29] & reg_we) & ~wr_err;
	assign ctrl_shadowed_key_len_wd = reg_wdata[9:7];
	assign ctrl_shadowed_key_len_re = addr_hit[29] && reg_re;
	assign ctrl_shadowed_manual_operation_we = (addr_hit[29] & reg_we) & ~wr_err;
	assign ctrl_shadowed_manual_operation_wd = reg_wdata[10];
	assign ctrl_shadowed_manual_operation_re = addr_hit[29] && reg_re;
	assign ctrl_shadowed_force_zero_masks_we = (addr_hit[29] & reg_we) & ~wr_err;
	assign ctrl_shadowed_force_zero_masks_wd = reg_wdata[11];
	assign ctrl_shadowed_force_zero_masks_re = addr_hit[29] && reg_re;
	assign trigger_start_we = (addr_hit[30] & reg_we) & ~wr_err;
	assign trigger_start_wd = reg_wdata[0];
	assign trigger_key_clear_we = (addr_hit[30] & reg_we) & ~wr_err;
	assign trigger_key_clear_wd = reg_wdata[1];
	assign trigger_iv_clear_we = (addr_hit[30] & reg_we) & ~wr_err;
	assign trigger_iv_clear_wd = reg_wdata[2];
	assign trigger_data_in_clear_we = (addr_hit[30] & reg_we) & ~wr_err;
	assign trigger_data_in_clear_wd = reg_wdata[3];
	assign trigger_data_out_clear_we = (addr_hit[30] & reg_we) & ~wr_err;
	assign trigger_data_out_clear_wd = reg_wdata[4];
	assign trigger_prng_reseed_we = (addr_hit[30] & reg_we) & ~wr_err;
	assign trigger_prng_reseed_wd = reg_wdata[5];
	always @(*) begin
		reg_rdata_next = 1'sb0;
		case (1'b1)
			addr_hit[0]: begin
				reg_rdata_next[0] = 1'sb0;
				reg_rdata_next[1] = 1'sb0;
			end
			addr_hit[1]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[2]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[3]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[4]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[5]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[6]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[7]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[8]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[9]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[10]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[11]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[12]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[13]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[14]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[15]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[16]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[17]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[18]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[19]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[20]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[21]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[22]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[23]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[24]: reg_rdata_next[31:0] = 1'sb0;
			addr_hit[25]: reg_rdata_next[31:0] = data_out_0_qs;
			addr_hit[26]: reg_rdata_next[31:0] = data_out_1_qs;
			addr_hit[27]: reg_rdata_next[31:0] = data_out_2_qs;
			addr_hit[28]: reg_rdata_next[31:0] = data_out_3_qs;
			addr_hit[29]: begin
				reg_rdata_next[0] = ctrl_shadowed_operation_qs;
				reg_rdata_next[6:1] = ctrl_shadowed_mode_qs;
				reg_rdata_next[9:7] = ctrl_shadowed_key_len_qs;
				reg_rdata_next[10] = ctrl_shadowed_manual_operation_qs;
				reg_rdata_next[11] = ctrl_shadowed_force_zero_masks_qs;
			end
			addr_hit[30]: begin
				reg_rdata_next[0] = 1'sb0;
				reg_rdata_next[1] = 1'sb0;
				reg_rdata_next[2] = 1'sb0;
				reg_rdata_next[3] = 1'sb0;
				reg_rdata_next[4] = 1'sb0;
				reg_rdata_next[5] = 1'sb0;
			end
			addr_hit[31]: begin
				reg_rdata_next[0] = status_idle_qs;
				reg_rdata_next[1] = status_stall_qs;
				reg_rdata_next[2] = status_output_valid_qs;
				reg_rdata_next[3] = status_input_ready_qs;
				reg_rdata_next[4] = status_ctrl_err_storage_qs;
			end
			default: reg_rdata_next = 1'sb1;
		endcase
	end
endmodule
module aes_sbox_canright_masked_noreuse (
	op_i,
	data_i,
	in_mask_i,
	out_mask_i,
	data_o
);
	input wire op_i;
	input wire [7:0] data_i;
	input wire [7:0] in_mask_i;
	input wire [7:0] out_mask_i;
	output wire [7:0] data_o;
	function automatic [1:0] aes_sbox_canright_pkg_aes_mul_gf2p2;
		input reg [1:0] g;
		input reg [1:0] d;
		reg [1:0] f;
		reg a;
		reg b;
		reg c;
		begin
			a = g[1] & d[1];
			b = ^g & ^d;
			c = g[0] & d[0];
			f[1] = a ^ b;
			f[0] = c ^ b;
			aes_sbox_canright_pkg_aes_mul_gf2p2 = f;
		end
	endfunction
	function automatic [1:0] aes_sbox_canright_pkg_aes_scale_omega2_gf2p2;
		input reg [1:0] g;
		reg [1:0] d;
		begin
			d[1] = g[0];
			d[0] = g[1] ^ g[0];
			aes_sbox_canright_pkg_aes_scale_omega2_gf2p2 = d;
		end
	endfunction
	function automatic [1:0] aes_sbox_canright_pkg_aes_square_gf2p2;
		input reg [1:0] g;
		reg [1:0] d;
		begin
			d[1] = g[0];
			d[0] = g[1];
			aes_sbox_canright_pkg_aes_square_gf2p2 = d;
		end
	endfunction
	function automatic [3:0] aes_masked_inverse_gf2p4;
		input reg [3:0] b;
		input reg [3:0] q;
		input reg [1:0] r;
		input reg [3:0] t;
		reg [3:0] b_inv;
		reg [1:0] b1;
		reg [1:0] b0;
		reg [1:0] q1;
		reg [1:0] q0;
		reg [1:0] c;
		reg [1:0] c_inv;
		reg [1:0] r_sq;
		reg [1:0] t1;
		reg [1:0] t0;
		reg [1:0] b1_inv;
		reg [1:0] b0_inv;
		begin
			b1 = b[3:2];
			b0 = b[1:0];
			q1 = q[3:2];
			q0 = q[1:0];
			t1 = t[3:2];
			t0 = t[1:0];
			c = (((((r ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(aes_sbox_canright_pkg_aes_square_gf2p2(b1 ^ b0))) ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(aes_sbox_canright_pkg_aes_square_gf2p2(q1 ^ q0))) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b1, b0)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b1, q0)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b0, q1)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(q1, q0);
			c_inv = aes_sbox_canright_pkg_aes_square_gf2p2(c);
			r_sq = aes_sbox_canright_pkg_aes_square_gf2p2(r);
			b1_inv = (((t1 ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b0, c_inv)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b0, r_sq)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(q0, c_inv)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(q0, r_sq);
			b0_inv = (((t0 ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b1, c_inv)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b1, r_sq)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(q1, c_inv)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(q1, r_sq);
			b_inv = {b1_inv, b0_inv};
			aes_masked_inverse_gf2p4 = b_inv;
		end
	endfunction
	function automatic [3:0] aes_sbox_canright_pkg_aes_mul_gf2p4;
		input reg [3:0] gamma;
		input reg [3:0] delta;
		reg [3:0] theta;
		reg [1:0] a;
		reg [1:0] b;
		reg [1:0] c;
		begin
			a = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[3:2], delta[3:2]);
			b = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[3:2] ^ gamma[1:0], delta[3:2] ^ delta[1:0]);
			c = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[1:0], delta[1:0]);
			theta[3:2] = a ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(b);
			theta[1:0] = c ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(b);
			aes_sbox_canright_pkg_aes_mul_gf2p4 = theta;
		end
	endfunction
	function automatic [1:0] aes_sbox_canright_pkg_aes_scale_omega_gf2p2;
		input reg [1:0] g;
		reg [1:0] d;
		begin
			d[1] = g[1] ^ g[0];
			d[0] = g[1];
			aes_sbox_canright_pkg_aes_scale_omega_gf2p2 = d;
		end
	endfunction
	function automatic [3:0] aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2;
		input reg [3:0] gamma;
		reg [3:0] delta;
		reg [1:0] a;
		reg [1:0] b;
		begin
			a = gamma[3:2] ^ gamma[1:0];
			b = aes_sbox_canright_pkg_aes_square_gf2p2(gamma[1:0]);
			delta[3:2] = aes_sbox_canright_pkg_aes_square_gf2p2(a);
			delta[1:0] = aes_sbox_canright_pkg_aes_scale_omega_gf2p2(b);
			aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2 = delta;
		end
	endfunction
	function automatic [7:0] aes_masked_inverse_gf2p8;
		input reg [7:0] a;
		input reg [7:0] m;
		input reg [7:0] n;
		reg [7:0] a_inv;
		reg [3:0] a1;
		reg [3:0] a0;
		reg [3:0] m1;
		reg [3:0] m0;
		reg [3:0] b;
		reg [3:0] b_inv;
		reg [3:0] q;
		reg [3:0] s1;
		reg [3:0] s0;
		reg [3:0] t;
		reg [3:0] a1_inv;
		reg [3:0] a0_inv;
		reg [1:0] r;
		begin
			a1 = a[7:4];
			a0 = a[3:0];
			m1 = m[7:4];
			m0 = m[3:0];
			q = n[7:4];
			b = (((((q ^ aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2(a1 ^ a0)) ^ aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2(m1 ^ m0)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a1, a0)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a1, m0)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a0, m1)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(m1, m0);
			r = m1[3:2];
			t = q;
			b_inv = aes_masked_inverse_gf2p4(b, q, r, t);
			s1 = m1;
			s0 = m0;
			a1_inv = (((s1 ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a0, b_inv)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a0, t)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(m0, b_inv)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(m0, t);
			a0_inv = (((s0 ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a1, b_inv)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a1, t)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(m1, b_inv)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(m1, t);
			a_inv = {a1_inv, a0_inv};
			a_inv = (a_inv ^ n) ^ m;
			aes_masked_inverse_gf2p8 = a_inv;
		end
	endfunction
	wire [7:0] data_basis_x;
	wire [7:0] data_inverse;
	wire [7:0] in_mask_basis_x;
	wire [7:0] out_mask_basis_x;
	function automatic [7:0] aes_pkg_aes_mvm;
		input reg [7:0] vec_b;
		input reg [63:0] mat_a;
		reg [7:0] vec_c;
		begin
			vec_c = 1'sb0;
			begin : sv2v_autoblock_1
				reg signed [31:0] i;
				for (i = 0; i < 8; i = i + 1)
					begin : sv2v_autoblock_2
						reg signed [31:0] j;
						for (j = 0; j < 8; j = j + 1)
							vec_c[i] = vec_c[i] ^ (mat_a[((7 - j) * 8) + i] & vec_b[7 - j]);
					end
			end
			aes_pkg_aes_mvm = vec_c;
		end
	endfunction
	localparam [63:0] aes_sbox_canright_pkg_A2X = 64'h98f3f2480981a9ff;
	localparam [63:0] aes_sbox_canright_pkg_S2X = 64'h8c7905eb12045153;
	assign data_basis_x = (op_i == 1'b0 ? aes_pkg_aes_mvm(data_i, aes_sbox_canright_pkg_A2X) : aes_pkg_aes_mvm(data_i ^ 8'h63, aes_sbox_canright_pkg_S2X));
	assign in_mask_basis_x = (op_i == 1'b0 ? aes_pkg_aes_mvm(in_mask_i, aes_sbox_canright_pkg_A2X) : aes_pkg_aes_mvm(in_mask_i, aes_sbox_canright_pkg_S2X));
	assign out_mask_basis_x = (op_i == 1'b1 ? aes_pkg_aes_mvm(out_mask_i, aes_sbox_canright_pkg_A2X) : aes_pkg_aes_mvm(out_mask_i, aes_sbox_canright_pkg_S2X));
	assign data_inverse = aes_masked_inverse_gf2p8(data_basis_x, in_mask_basis_x, out_mask_basis_x);
	localparam [63:0] aes_sbox_canright_pkg_X2A = 64'h64786e8c6829de60;
	localparam [63:0] aes_sbox_canright_pkg_X2S = 64'h582d9e0bdc040324;
	assign data_o = (op_i == 1'b0 ? aes_pkg_aes_mvm(data_inverse, aes_sbox_canright_pkg_X2S) ^ 8'h63 : aes_pkg_aes_mvm(data_inverse, aes_sbox_canright_pkg_X2A));
endmodule
module aes_sbox_canright_masked (
	op_i,
	data_i,
	in_mask_i,
	out_mask_i,
	data_o
);
	input wire op_i;
	input wire [7:0] data_i;
	input wire [7:0] in_mask_i;
	input wire [7:0] out_mask_i;
	output wire [7:0] data_o;
	function automatic [1:0] aes_sbox_canright_pkg_aes_mul_gf2p2;
		input reg [1:0] g;
		input reg [1:0] d;
		reg [1:0] f;
		reg a;
		reg b;
		reg c;
		begin
			a = g[1] & d[1];
			b = ^g & ^d;
			c = g[0] & d[0];
			f[1] = a ^ b;
			f[0] = c ^ b;
			aes_sbox_canright_pkg_aes_mul_gf2p2 = f;
		end
	endfunction
	function automatic [1:0] aes_sbox_canright_pkg_aes_scale_omega2_gf2p2;
		input reg [1:0] g;
		reg [1:0] d;
		begin
			d[1] = g[0];
			d[0] = g[1] ^ g[0];
			aes_sbox_canright_pkg_aes_scale_omega2_gf2p2 = d;
		end
	endfunction
	function automatic [1:0] aes_sbox_canright_pkg_aes_square_gf2p2;
		input reg [1:0] g;
		reg [1:0] d;
		begin
			d[1] = g[0];
			d[0] = g[1];
			aes_sbox_canright_pkg_aes_square_gf2p2 = d;
		end
	endfunction
	function automatic [3:0] aes_masked_inverse_gf2p4;
		input reg [3:0] b;
		input reg [3:0] q;
		input reg [1:0] r;
		input reg [3:0] m1;
		reg [3:0] b_inv;
		reg [1:0] b1;
		reg [1:0] b0;
		reg [1:0] q1;
		reg [1:0] q0;
		reg [1:0] c;
		reg [1:0] c_inv;
		reg [1:0] c2_inv;
		reg [1:0] r_sq;
		reg [1:0] m11;
		reg [1:0] m10;
		reg [1:0] b1_inv;
		reg [1:0] b0_inv;
		reg [1:0] mul_b0_q1;
		reg [1:0] mul_b1_q0;
		reg [1:0] mul_q0_q1;
		begin
			b1 = b[3:2];
			b0 = b[1:0];
			q1 = q[3:2];
			q0 = q[1:0];
			m11 = m1[3:2];
			m10 = m1[1:0];
			mul_b0_q1 = aes_sbox_canright_pkg_aes_mul_gf2p2(b0, q1);
			mul_b1_q0 = aes_sbox_canright_pkg_aes_mul_gf2p2(b1, q0);
			mul_q0_q1 = aes_sbox_canright_pkg_aes_mul_gf2p2(q0, q1);
			c = (((((r ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(aes_sbox_canright_pkg_aes_square_gf2p2(b1 ^ b0))) ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(aes_sbox_canright_pkg_aes_square_gf2p2(q1 ^ q0))) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b1, b0)) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b1, q0)) ^ mul_b0_q1) ^ mul_q0_q1;
			c_inv = aes_sbox_canright_pkg_aes_square_gf2p2(c);
			r_sq = aes_sbox_canright_pkg_aes_square_gf2p2(r);
			c_inv = c_inv ^ (q1 ^ r_sq);
			c2_inv = c_inv ^ (q0 ^ q1);
			b1_inv = (((m11 ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b0, c_inv)) ^ mul_b0_q1) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(q0, c_inv)) ^ mul_q0_q1;
			b0_inv = (((m10 ^ aes_sbox_canright_pkg_aes_mul_gf2p2(b1, c2_inv)) ^ mul_b1_q0) ^ aes_sbox_canright_pkg_aes_mul_gf2p2(q1, c2_inv)) ^ mul_q0_q1;
			b_inv = {b1_inv, b0_inv};
			aes_masked_inverse_gf2p4 = b_inv;
		end
	endfunction
	function automatic [3:0] aes_sbox_canright_pkg_aes_mul_gf2p4;
		input reg [3:0] gamma;
		input reg [3:0] delta;
		reg [3:0] theta;
		reg [1:0] a;
		reg [1:0] b;
		reg [1:0] c;
		begin
			a = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[3:2], delta[3:2]);
			b = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[3:2] ^ gamma[1:0], delta[3:2] ^ delta[1:0]);
			c = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[1:0], delta[1:0]);
			theta[3:2] = a ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(b);
			theta[1:0] = c ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(b);
			aes_sbox_canright_pkg_aes_mul_gf2p4 = theta;
		end
	endfunction
	function automatic [1:0] aes_sbox_canright_pkg_aes_scale_omega_gf2p2;
		input reg [1:0] g;
		reg [1:0] d;
		begin
			d[1] = g[1] ^ g[0];
			d[0] = g[1];
			aes_sbox_canright_pkg_aes_scale_omega_gf2p2 = d;
		end
	endfunction
	function automatic [3:0] aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2;
		input reg [3:0] gamma;
		reg [3:0] delta;
		reg [1:0] a;
		reg [1:0] b;
		begin
			a = gamma[3:2] ^ gamma[1:0];
			b = aes_sbox_canright_pkg_aes_square_gf2p2(gamma[1:0]);
			delta[3:2] = aes_sbox_canright_pkg_aes_square_gf2p2(a);
			delta[1:0] = aes_sbox_canright_pkg_aes_scale_omega_gf2p2(b);
			aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2 = delta;
		end
	endfunction
	function automatic [7:0] aes_masked_inverse_gf2p8;
		input reg [7:0] a;
		input reg [7:0] m;
		input reg [7:0] n;
		reg [7:0] a_inv;
		reg [3:0] a1;
		reg [3:0] a0;
		reg [3:0] m1;
		reg [3:0] m0;
		reg [3:0] b;
		reg [3:0] b_inv;
		reg [3:0] b2_inv;
		reg [3:0] q;
		reg [3:0] s1;
		reg [3:0] s0;
		reg [3:0] a1_inv;
		reg [3:0] a0_inv;
		reg [3:0] mul_a0_m1;
		reg [3:0] mul_a1_m0;
		reg [3:0] mul_m0_m1;
		reg [1:0] r;
		begin
			a1 = a[7:4];
			a0 = a[3:0];
			m1 = m[7:4];
			m0 = m[3:0];
			mul_a0_m1 = aes_sbox_canright_pkg_aes_mul_gf2p4(a0, m1);
			mul_a1_m0 = aes_sbox_canright_pkg_aes_mul_gf2p4(a1, m0);
			mul_m0_m1 = aes_sbox_canright_pkg_aes_mul_gf2p4(m0, m1);
			q = n[7:4];
			b = (((((q ^ aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2(a1 ^ a0)) ^ aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2(m1 ^ m0)) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a1, a0)) ^ mul_a1_m0) ^ mul_a0_m1) ^ mul_m0_m1;
			r = m1[3:2];
			b_inv = aes_masked_inverse_gf2p4(b, q, r, m1);
			b2_inv = b_inv ^ (m1 ^ m0);
			s1 = n[7:4];
			s0 = n[3:0];
			a1_inv = (((s1 ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a0, b_inv)) ^ mul_a0_m1) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(m0, b_inv)) ^ mul_m0_m1;
			a0_inv = (((s0 ^ aes_sbox_canright_pkg_aes_mul_gf2p4(a1, b2_inv)) ^ mul_a1_m0) ^ aes_sbox_canright_pkg_aes_mul_gf2p4(m1, b2_inv)) ^ mul_m0_m1;
			a_inv = {a1_inv, a0_inv};
			aes_masked_inverse_gf2p8 = a_inv;
		end
	endfunction
	wire [7:0] data_basis_x;
	wire [7:0] data_inverse;
	wire [7:0] in_mask_basis_x;
	wire [7:0] out_mask_basis_x;
	function automatic [7:0] aes_pkg_aes_mvm;
		input reg [7:0] vec_b;
		input reg [63:0] mat_a;
		reg [7:0] vec_c;
		begin
			vec_c = 1'sb0;
			begin : sv2v_autoblock_1
				reg signed [31:0] i;
				for (i = 0; i < 8; i = i + 1)
					begin : sv2v_autoblock_2
						reg signed [31:0] j;
						for (j = 0; j < 8; j = j + 1)
							vec_c[i] = vec_c[i] ^ (mat_a[((7 - j) * 8) + i] & vec_b[7 - j]);
					end
			end
			aes_pkg_aes_mvm = vec_c;
		end
	endfunction
	localparam [63:0] aes_sbox_canright_pkg_A2X = 64'h98f3f2480981a9ff;
	localparam [63:0] aes_sbox_canright_pkg_S2X = 64'h8c7905eb12045153;
	assign data_basis_x = (op_i == 1'b0 ? aes_pkg_aes_mvm(data_i, aes_sbox_canright_pkg_A2X) : aes_pkg_aes_mvm(data_i ^ 8'h63, aes_sbox_canright_pkg_S2X));
	assign in_mask_basis_x = (op_i == 1'b0 ? aes_pkg_aes_mvm(in_mask_i, aes_sbox_canright_pkg_A2X) : aes_pkg_aes_mvm(in_mask_i, aes_sbox_canright_pkg_S2X));
	assign out_mask_basis_x = (op_i == 1'b1 ? aes_pkg_aes_mvm(out_mask_i, aes_sbox_canright_pkg_A2X) : aes_pkg_aes_mvm(out_mask_i, aes_sbox_canright_pkg_S2X));
	assign data_inverse = aes_masked_inverse_gf2p8(data_basis_x, in_mask_basis_x, out_mask_basis_x);
	localparam [63:0] aes_sbox_canright_pkg_X2A = 64'h64786e8c6829de60;
	localparam [63:0] aes_sbox_canright_pkg_X2S = 64'h582d9e0bdc040324;
	assign data_o = (op_i == 1'b0 ? aes_pkg_aes_mvm(data_inverse, aes_sbox_canright_pkg_X2S) ^ 8'h63 : aes_pkg_aes_mvm(data_inverse, aes_sbox_canright_pkg_X2A));
endmodule
module aes_sbox_canright (
	op_i,
	data_i,
	data_o
);
	input wire op_i;
	input wire [7:0] data_i;
	output wire [7:0] data_o;
	function automatic [1:0] aes_sbox_canright_pkg_aes_mul_gf2p2;
		input reg [1:0] g;
		input reg [1:0] d;
		reg [1:0] f;
		reg a;
		reg b;
		reg c;
		begin
			a = g[1] & d[1];
			b = ^g & ^d;
			c = g[0] & d[0];
			f[1] = a ^ b;
			f[0] = c ^ b;
			aes_sbox_canright_pkg_aes_mul_gf2p2 = f;
		end
	endfunction
	function automatic [1:0] aes_sbox_canright_pkg_aes_scale_omega2_gf2p2;
		input reg [1:0] g;
		reg [1:0] d;
		begin
			d[1] = g[0];
			d[0] = g[1] ^ g[0];
			aes_sbox_canright_pkg_aes_scale_omega2_gf2p2 = d;
		end
	endfunction
	function automatic [1:0] aes_sbox_canright_pkg_aes_square_gf2p2;
		input reg [1:0] g;
		reg [1:0] d;
		begin
			d[1] = g[0];
			d[0] = g[1];
			aes_sbox_canright_pkg_aes_square_gf2p2 = d;
		end
	endfunction
	function automatic [3:0] aes_inverse_gf2p4;
		input reg [3:0] gamma;
		reg [3:0] delta;
		reg [1:0] a;
		reg [1:0] b;
		reg [1:0] c;
		reg [1:0] d;
		begin
			a = gamma[3:2] ^ gamma[1:0];
			b = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[3:2], gamma[1:0]);
			c = aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(aes_sbox_canright_pkg_aes_square_gf2p2(a));
			d = aes_sbox_canright_pkg_aes_square_gf2p2(c ^ b);
			delta[3:2] = aes_sbox_canright_pkg_aes_mul_gf2p2(d, gamma[1:0]);
			delta[1:0] = aes_sbox_canright_pkg_aes_mul_gf2p2(d, gamma[3:2]);
			aes_inverse_gf2p4 = delta;
		end
	endfunction
	function automatic [3:0] aes_sbox_canright_pkg_aes_mul_gf2p4;
		input reg [3:0] gamma;
		input reg [3:0] delta;
		reg [3:0] theta;
		reg [1:0] a;
		reg [1:0] b;
		reg [1:0] c;
		begin
			a = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[3:2], delta[3:2]);
			b = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[3:2] ^ gamma[1:0], delta[3:2] ^ delta[1:0]);
			c = aes_sbox_canright_pkg_aes_mul_gf2p2(gamma[1:0], delta[1:0]);
			theta[3:2] = a ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(b);
			theta[1:0] = c ^ aes_sbox_canright_pkg_aes_scale_omega2_gf2p2(b);
			aes_sbox_canright_pkg_aes_mul_gf2p4 = theta;
		end
	endfunction
	function automatic [1:0] aes_sbox_canright_pkg_aes_scale_omega_gf2p2;
		input reg [1:0] g;
		reg [1:0] d;
		begin
			d[1] = g[1] ^ g[0];
			d[0] = g[1];
			aes_sbox_canright_pkg_aes_scale_omega_gf2p2 = d;
		end
	endfunction
	function automatic [3:0] aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2;
		input reg [3:0] gamma;
		reg [3:0] delta;
		reg [1:0] a;
		reg [1:0] b;
		begin
			a = gamma[3:2] ^ gamma[1:0];
			b = aes_sbox_canright_pkg_aes_square_gf2p2(gamma[1:0]);
			delta[3:2] = aes_sbox_canright_pkg_aes_square_gf2p2(a);
			delta[1:0] = aes_sbox_canright_pkg_aes_scale_omega_gf2p2(b);
			aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2 = delta;
		end
	endfunction
	function automatic [7:0] aes_inverse_gf2p8;
		input reg [7:0] gamma;
		reg [7:0] delta;
		reg [3:0] a;
		reg [3:0] b;
		reg [3:0] c;
		reg [3:0] d;
		begin
			a = gamma[7:4] ^ gamma[3:0];
			b = aes_sbox_canright_pkg_aes_mul_gf2p4(gamma[7:4], gamma[3:0]);
			c = aes_sbox_canright_pkg_aes_square_scale_gf2p4_gf2p2(a);
			d = aes_inverse_gf2p4(c ^ b);
			delta[7:4] = aes_sbox_canright_pkg_aes_mul_gf2p4(d, gamma[3:0]);
			delta[3:0] = aes_sbox_canright_pkg_aes_mul_gf2p4(d, gamma[7:4]);
			aes_inverse_gf2p8 = delta;
		end
	endfunction
	wire [7:0] data_basis_x;
	wire [7:0] data_inverse;
	function automatic [7:0] aes_pkg_aes_mvm;
		input reg [7:0] vec_b;
		input reg [63:0] mat_a;
		reg [7:0] vec_c;
		begin
			vec_c = 1'sb0;
			begin : sv2v_autoblock_1
				reg signed [31:0] i;
				for (i = 0; i < 8; i = i + 1)
					begin : sv2v_autoblock_2
						reg signed [31:0] j;
						for (j = 0; j < 8; j = j + 1)
							vec_c[i] = vec_c[i] ^ (mat_a[((7 - j) * 8) + i] & vec_b[7 - j]);
					end
			end
			aes_pkg_aes_mvm = vec_c;
		end
	endfunction
	localparam [63:0] aes_sbox_canright_pkg_A2X = 64'h98f3f2480981a9ff;
	localparam [63:0] aes_sbox_canright_pkg_S2X = 64'h8c7905eb12045153;
	assign data_basis_x = (op_i == 1'b0 ? aes_pkg_aes_mvm(data_i, aes_sbox_canright_pkg_A2X) : aes_pkg_aes_mvm(data_i ^ 8'h63, aes_sbox_canright_pkg_S2X));
	assign data_inverse = aes_inverse_gf2p8(data_basis_x);
	localparam [63:0] aes_sbox_canright_pkg_X2A = 64'h64786e8c6829de60;
	localparam [63:0] aes_sbox_canright_pkg_X2S = 64'h582d9e0bdc040324;
	assign data_o = (op_i == 1'b0 ? aes_pkg_aes_mvm(data_inverse, aes_sbox_canright_pkg_X2S) ^ 8'h63 : aes_pkg_aes_mvm(data_inverse, aes_sbox_canright_pkg_X2A));
endmodule
module aes_sbox_lut (
	op_i,
	data_i,
	data_o
);
	input wire op_i;
	input wire [7:0] data_i;
	output wire [7:0] data_o;
	localparam [2047:0] SBOX_FWD = 2048'h637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16;
	localparam [2047:0] SBOX_INV = 2048'h52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d;
	assign data_o = (op_i == 1'b0 ? SBOX_FWD[(255 - data_i) * 8+:8] : SBOX_INV[(255 - data_i) * 8+:8]);
endmodule
module aes_sbox (
	op_i,
	data_i,
	in_mask_i,
	out_mask_i,
	data_o
);
	parameter integer SBoxImpl = 32'sd0;
	input wire op_i;
	input wire [7:0] data_i;
	input wire [7:0] in_mask_i;
	input wire [7:0] out_mask_i;
	output wire [7:0] data_o;
	localparam [0:0] SBoxMasked = ((SBoxImpl == 32'sd2) || (SBoxImpl == 32'sd3) ? 1'b1 : 1'b0);
	generate
		if (!SBoxMasked) begin : gen_sbox_unmasked
			wire [15:0] unused_masks;
			assign unused_masks = {in_mask_i, out_mask_i};
			if (SBoxImpl == 32'sd1) begin : gen_sbox_canright
				aes_sbox_canright u_aes_sbox(
					.op_i(op_i),
					.data_i(data_i),
					.data_o(data_o)
				);
			end
			else begin : gen_sbox_lut
				aes_sbox_lut u_aes_sbox(
					.op_i(op_i),
					.data_i(data_i),
					.data_o(data_o)
				);
			end
		end
		else begin : gen_sbox_masked
			if (SBoxImpl == 32'sd3) begin : gen_sbox_canright_masked_noreuse
				aes_sbox_canright_masked_noreuse u_aes_sbox(
					.op_i(op_i),
					.data_i(data_i),
					.in_mask_i(in_mask_i),
					.out_mask_i(out_mask_i),
					.data_o(data_o)
				);
			end
			else begin : gen_sbox_canright_masked
				aes_sbox_canright_masked u_aes_sbox(
					.op_i(op_i),
					.data_i(data_i),
					.in_mask_i(in_mask_i),
					.out_mask_i(out_mask_i),
					.data_o(data_o)
				);
			end
		end
	endgenerate
endmodule
module aes_shift_rows (
	op_i,
	data_i,
	data_o
);
	input wire op_i;
	input wire [127:0] data_i;
	output wire [127:0] data_o;
	assign data_o[0+:32] = data_i[0+:32];
	function automatic [31:0] aes_pkg_aes_circ_byte_shift;
		input reg [31:0] in;
		input reg [1:0] shift;
		reg [31:0] out;
		reg [31:0] s;
		begin
			s = {30'b000000000000000000000000000000, shift};
			out = {in[8 * ((7 - s) % 4)+:8], in[8 * ((6 - s) % 4)+:8], in[8 * ((5 - s) % 4)+:8], in[8 * ((4 - s) % 4)+:8]};
			aes_pkg_aes_circ_byte_shift = out;
		end
	endfunction
	assign data_o[64+:32] = aes_pkg_aes_circ_byte_shift(data_i[64+:32], 2'h2);
	assign data_o[32+:32] = (op_i == 1'b0 ? aes_pkg_aes_circ_byte_shift(data_i[32+:32], 2'h3) : aes_pkg_aes_circ_byte_shift(data_i[32+:32], 2'h1));
	assign data_o[96+:32] = (op_i == 1'b0 ? aes_pkg_aes_circ_byte_shift(data_i[96+:32], 2'h1) : aes_pkg_aes_circ_byte_shift(data_i[96+:32], 2'h3));
endmodule
module aes_sub_bytes (
	op_i,
	data_i,
	in_mask_i,
	out_mask_i,
	data_o
);
	parameter integer SBoxImpl = 32'sd0;
	input wire op_i;
	input wire [127:0] data_i;
	input wire [127:0] in_mask_i;
	input wire [127:0] out_mask_i;
	output wire [127:0] data_o;
	genvar j;
	generate
		for (j = 0; j < 4; j = j + 1) begin : gen_sbox_j
			genvar i;
			for (i = 0; i < 4; i = i + 1) begin : gen_sbox_i
				aes_sbox #(.SBoxImpl(SBoxImpl)) u_aes_sbox_ij(
					.op_i(op_i),
					.data_i(data_i[((i * 4) + j) * 8+:8]),
					.in_mask_i(in_mask_i[((i * 4) + j) * 8+:8]),
					.out_mask_i(out_mask_i[((i * 4) + j) * 8+:8]),
					.data_o(data_o[((i * 4) + j) * 8+:8])
				);
			end
		end
	endgenerate
endmodule
module aes (
	clk_i,
	rst_ni,
	idle_o,
	tl_i,
	tl_o,
	alert_rx_i,
	alert_tx_o
);
	parameter [0:0] AES192Enable = 1;
	parameter [0:0] Masking = 0;
	parameter integer SBoxImpl = 32'sd0;
	parameter [31:0] SecStartTriggerDelay = 0;
	parameter [0:0] SecAllowForcingMasks = 0;
	localparam [31:0] aes_pkg_WidthPRDClearing = 64;
	localparam [63:0] aes_pkg_DefaultSeedClearing = 64'hfedcba9876543210;
	parameter [63:0] SeedClearing = aes_pkg_DefaultSeedClearing;
	localparam [31:0] aes_pkg_WidthPRDData = 128;
	localparam [31:0] aes_pkg_WidthPRDKey = 32;
	localparam [31:0] aes_pkg_WidthPRDMasking = aes_pkg_WidthPRDData + aes_pkg_WidthPRDKey;
	localparam [aes_pkg_WidthPRDMasking - 1:0] aes_pkg_DefaultSeedMasking = 160'h0000000500000004000000030000000200000001;
	parameter [aes_pkg_WidthPRDMasking - 1:0] SeedMasking = aes_pkg_DefaultSeedMasking;
	localparam signed [31:0] aes_reg_pkg_NumAlerts = 2;
	parameter [1:0] AlertAsyncOn = {aes_reg_pkg_NumAlerts {1'b1}};
	input wire clk_i;
	input wire rst_ni;
	output wire idle_o;
	localparam signed [31:0] top_pkg_TL_AIW = 8;
	localparam signed [31:0] top_pkg_TL_AW = 32;
	localparam signed [31:0] top_pkg_TL_DW = 32;
	localparam signed [31:0] top_pkg_TL_DBW = top_pkg_TL_DW >> 3;
	localparam signed [31:0] top_pkg_TL_SZW = $clog2($clog2(top_pkg_TL_DBW) + 1);
	input wire [(((((7 + top_pkg_TL_SZW) + top_pkg_TL_AIW) + top_pkg_TL_AW) + top_pkg_TL_DBW) + top_pkg_TL_DW) + 16:0] tl_i;
	localparam signed [31:0] top_pkg_TL_DIW = 1;
	localparam signed [31:0] top_pkg_TL_DUW = 16;
	output wire [(((((7 + top_pkg_TL_SZW) + top_pkg_TL_AIW) + top_pkg_TL_DIW) + top_pkg_TL_DW) + top_pkg_TL_DUW) + 1:0] tl_o;
	input wire [7:0] alert_rx_i;
	output wire [3:0] alert_tx_o;
	wire [955:0] reg2hw;
	wire [933:0] hw2reg;
	wire [1:0] alert;
	aes_reg_top u_reg(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.tl_i(tl_i),
		.tl_o(tl_o),
		.reg2hw(reg2hw),
		.hw2reg(hw2reg),
		.devmode_i(1'b1)
	);
	aes_core #(
		.AES192Enable(AES192Enable),
		.Masking(Masking),
		.SBoxImpl(SBoxImpl),
		.SecStartTriggerDelay(SecStartTriggerDelay),
		.SecAllowForcingMasks(SecAllowForcingMasks),
		.SeedClearing(SeedClearing),
		.SeedMasking(SeedMasking)
	) u_aes_core(
		.clk_i(clk_i),
		.rst_ni(rst_ni),
		.entropy_clearing_ack_i(1'b1),
		.entropy_clearing_i(aes_pkg_DefaultSeedClearing),
		.entropy_masking_ack_i(1'b1),
		.entropy_masking_i(aes_pkg_DefaultSeedMasking),
		.ctrl_err_update_o(alert[0]),
		.ctrl_err_storage_o(alert[1]),
		.reg2hw(reg2hw),
		.hw2reg(hw2reg)
	);
	assign idle_o = hw2reg[9];
	wire [1:0] alert_test;
	assign alert_test = {reg2hw[953] & reg2hw[952], reg2hw[955] & reg2hw[954]};
	genvar i;
	generate
		for (i = 0; i < aes_reg_pkg_NumAlerts; i = i + 1) begin : gen_alert_tx
			prim_alert_sender #(.AsyncOn(AlertAsyncOn[i])) u_alert_sender_i(
				.clk_i(clk_i),
				.rst_ni(rst_ni),
				.alert_req_i(alert[i] | alert_test[i]),
				.alert_ack_o(),
				.alert_rx_i(alert_rx_i[i * 4+:4]),
				.alert_tx_o(alert_tx_o[i * 2+:2])
			);
		end
	endgenerate
endmodule
