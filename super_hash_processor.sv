module super_hash_processor(input logic clk, reset_n, start,
			input logic [1:0] opcode,
            input logic [31:0] message_addr, size, output_addr,
           output logic done, mem_clk, mem_we,
           output logic [15:0] mem_addr,
           output logic [31:0] mem_write_data,
            input logic [31:0] mem_read_data);


logic [31:0] w [0:15]; 
logic [31:0] hash[0:7];
logic [31:0] F,k,rW,sha1,t1,t2, new_W;
logic [9:0] pad_length;
logic [31:0] a,b,c,d,e,f,g,h;
logic [3:0] m, num_blocks, index, s7var;
logic [7:0] t;
logic [31:0] read_addr; 
logic [31:0] write_addr; 
logic read_signal;    
shortint size_word;

enum logic [2:0] {IDLE=3'b000, S1=3'b001, S2=3'b010, WRITE_PREP=3'b100, S5=3'b101, S7=3'b111, S10 = 3'b110} state;
			
assign mem_clk = clk;

// left rotation
function logic [31:0] leftrotate(input logic [31:0] x,
                                  input logic [7:0] r);
begin
    leftrotate = (x << r) | (x >> (32-r));
end
endfunction

function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [7:0] r);
begin
    rightrotate = (x >> r) | (x << (32-r));
end
endfunction

parameter byte S[0:15] = '{
    8'd7, 8'd12, 8'd17, 8'd22, 
    8'd5, 8'd9,  8'd14, 8'd20,
    8'd4, 8'd11, 8'd16, 8'd23,
    8'd6, 8'd10, 8'd15, 8'd21
};

parameter int md5_k[0:63] = '{
    32'hd76aa478, 32'he8c7b756, 32'h242070db, 32'hc1bdceee,
    32'hf57c0faf, 32'h4787c62a, 32'ha8304613, 32'hfd469501,
    32'h698098d8, 32'h8b44f7af, 32'hffff5bb1, 32'h895cd7be,
    32'h6b901122, 32'hfd987193, 32'ha679438e, 32'h49b40821,
    32'hf61e2562, 32'hc040b340, 32'h265e5a51, 32'he9b6c7aa,
    32'hd62f105d, 32'h02441453, 32'hd8a1e681, 32'he7d3fbc8,
    32'h21e1cde6, 32'hc33707d6, 32'hf4d50d87, 32'h455a14ed,
    32'ha9e3e905, 32'hfcefa3f8, 32'h676f02d9, 32'h8d2a4c8a,
    32'hfffa3942, 32'h8771f681, 32'h6d9d6122, 32'hfde5380c,
    32'ha4beea44, 32'h4bdecfa9, 32'hf6bb4b60, 32'hbebfbc70,
    32'h289b7ec6, 32'heaa127fa, 32'hd4ef3085, 32'h04881d05,
    32'hd9d4d039, 32'he6db99e5, 32'h1fa27cf8, 32'hc4ac5665,
    32'hf4292244, 32'h432aff97, 32'hab9423a7, 32'hfc93a039,
    32'h655b59c3, 32'h8f0ccc92, 32'hffeff47d, 32'h85845dd1,
    32'h6fa87e4f, 32'hfe2ce6e0, 32'ha3014314, 32'h4e0811a1,
    32'hf7537e82, 32'hbd3af235, 32'h2ad7d2bb, 32'heb86d391
};

parameter int sha256_k[0:63] = '{
   32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
   32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
   32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
   32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
   32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
   32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
   32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
   32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};

assign rW = changeEndian(mem_read_data);
assign mem_we = (read_signal == 1) ? 0 : 1;
assign mem_addr = (read_signal == 1) ? read_addr : write_addr;

// convert from little-endian to big-endian
function logic [31:0] changeEndian(input logic [31:0] value);
    changeEndian = {value[7:0], value[15:8], value[23:16], value[31:24]};
endfunction

function logic [159:0] sha1_op(input logic [31:0] a, b, c, d, e, w,
                               input logic [7:0] t);
begin
	if (t <= 19) begin 	
		F = (b & c) ^ ((~b) & d);
		k = 32'h5a827999;
		end
	else if ((t >= 20) && (t <= 39)) begin 	
		F = b ^ c ^ d ;
		k = 32'h6ed9eba1;
	end
	else if ((t >= 40) && (t <= 59)) begin 
		F = (b & c) ^ (b & d) ^ (c & d) ;
		k = 32'h8f1bbcdc;
	end
	else begin 
		F = b ^ c ^ d ;
		k = 32'hca62c1d6;
	end

    t1 = leftrotate(a,5) + F + w + k + e;
	t2 = leftrotate(b,30);
						
   sha1_op = {t1, a, t2, c, d};
end
endfunction

function logic [31:0] sIndex(input logic [5:0] t);
 logic [3:0] i;
 i = {t[5:4], t[1:0]};
 return S[i];
endfunction

function logic[3:0] md5_g(input logic [7:0] t);
begin
   if (t <= 31)
       md5_g = (5*t + 1) % 16;
   else if (t <= 47)
       md5_g = (3*t + 5) % 16;
   else
       md5_g = (7*t) % 16;
end
endfunction

function logic[127:0] md5_op(input logic [31:0] a, b, c, d, w,
                             input logic [7:0] t);
begin
	 if (t <= 15)
        F = (b & c) | ((~b) & d);
    else if (t <= 31)
        F = (d & b) | ((~d) & c);
    else if (t <= 47)
        F = b ^ c ^ d;
    else
        F = c ^ (b | (~d));
    t1 = a + F + md5_k[t] + w;
    t2 = b + leftrotate(t1, sIndex(t));
    md5_op = {d, t2, b, c};
end
endfunction

function logic [31:0] t1_comp(input logic[31:0] e,f,g,h,w,
						 input logic [7:0] t);
	logic [31:0] ch; 
begin
	k = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1_comp = h + k + ch + sha256_k[t] + w;
end	
endfunction

function logic [31:0] t2_comp(input logic[31:0] a,b,c);
logic [31:0] maj;
begin
	F = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2_comp = F + maj;
end	
endfunction

initial begin
m <= 1;
end

always_comb
begin
	if (size_word > 0)
		new_W = rW;
	else if (size_word == 0)
		new_W = delimiter(rW);
	else if (m == num_blocks && size_word < 0 && t == 15)
		new_W = (size << 3);
	else 
		new_W = 32'h00000000;
end

always_comb
begin
	case(opcode)
	2'b00:begin
	sha1 = 0;
	end
	2'b01:begin
	sha1 = leftrotate((w[13] ^ w[8] ^ w[2] ^ w[0]),1);
	end
	default:begin
	sha1 = ((rightrotate (w[1],7))^(rightrotate (w[1],18))^(w[1]>>3)) + ((rightrotate (w[14],17))^(rightrotate (w[14],19))^(w[14]>>10)) + w[0] + w[9];
	end
	endcase
	
end

always @(posedge clk, negedge reset_n)
begin
	if (!reset_n) begin
		state <= IDLE;
		done <= 0;
	end 
	else begin
		case (state)
			IDLE:
			begin
			if (start) begin 
					size_word <= (size/4) + 1;
					data_padding();
				case (opcode)
				2'b00: begin // md5
					hash[0] <= 32'h67452301;
					hash[1] <= 32'hEFCDAB89;
					hash[2] <= 32'h98BADCFE;
					hash[3] <= 32'h10325476;
					hash[4] <= 32'h00000000;
					hash[5] <= 32'h00000000;
					hash[6] <= 32'h00000000;
					hash[7] <= 32'h00000000;
					s7var <= 4;
				end
				
				2'b01: begin // sha1
					m <= 1;
					hash[0] <= 32'h67452301;
					hash[1] <= 32'hEFCDAB89;
					hash[2] <= 32'h98BADCFE;
					hash[3] <= 32'h10325476;
					hash[4] <= 32'hC3D2E1F0;
					hash[5] <= 32'h00000000;
					hash[6] <= 32'h00000000;
					hash[7] <= 32'h00000000;
					s7var <= 5;
				end
				
				default: begin // sha256
					m <= 1;
					hash[0] <= 32'h6a09e667;
					hash[1] <= 32'hbb67ae85;
					hash[2] <= 32'h3c6ef372;
					hash[3] <= 32'ha54ff53a;
					hash[4] <= 32'h510e527f;
					hash[5] <= 32'h9b05688c;
					hash[6] <= 32'h1f83d9ab;
					hash[7] <= 32'h5be0cd19;
					s7var <= 8;
				end
			endcase

			read_addr <= message_addr;
			write_addr <= output_addr;
			read_signal <= 1;
			state <= S1; end
			end
			
			S1:
			begin
				case (opcode)
				2'b00: begin // md5
					a <= hash[0];
					b <= hash[1];
					c <= hash[2];
					d <= hash[3];
				end
				2'b01: begin // sha1
					a <= hash[0];
					b <= hash[1];
					c <= hash[2];
					d <= hash[3];
					e <= hash[4];
				end
				default: begin // sha256
					a <= hash[0];
					b <= hash[1];
					c <= hash[2];
					d <= hash[3];
					e <= hash[4];
					f <= hash[5];
					g <= hash[6];
					h <= hash[7];
				end
			endcase
				
				t <= 0;
				state <= S2;
			end
			
			S2:
			begin
				read_addr <= read_addr + 1;
				size_word <= size_word - 1;
				state <= S5;
			end
			
			S5:
			begin
				case (opcode)
				2'b00: begin
					{a, b, c, d} <= md5_op(a, b, c, d, new_W, t);
					shift_array(new_W);
					t <= t + 1;
					read_addr <= read_addr + 1;
					size_word <= size_word - 1; 
					if (t == 15) begin
						index <= md5_g(t+1);
						state <= S10; end
					else
						state <= S5;
				end
				
				2'b01: begin 
					{a, b, c, d, e} <= sha1_op(a, b, c, d, e, new_W, t);
					shift_array(new_W); 
					t <= t + 1;
					read_addr <= read_addr + 1;
					size_word <= size_word - 1; 
					if (t == 15) begin
						state <= S10; end
					else
						state <= S5;
				end
						
				default:begin
						a <= t1_comp(e,f,g,h,new_W,t) + t2_comp(a,b,c) ;
						b <= a;
						c <= b;
						d <= c;
						e <= d + t1_comp(e,f,g,h,new_W,t);
						f <= e;
						g <= f;
						h <= g;
						shift_array(new_W); 
							
					t <= t + 1;
					read_addr <= read_addr + 1;
					size_word <= size_word - 1; 
					if (t == 15) begin
						state <= S10; end
					else
						state <= S5;
				end
			endcase	
			end
			
			S10:
			begin
				case(opcode)
				2'b00: begin
					if (t <= 63) begin
						{a, b, c, d} <= md5_op(a, b, c, d, w[index], t);
						index <= md5_g(t+1);
						t <= t + 1; end
					else begin
						hash[0] <= hash[0] + a;
						hash[1] <= hash[1] + b;
						hash[2] <= hash[2] + c;
						hash[3] <= hash[3] + d;
						size_word <= size_word + 1;
						m <= m + 1; 
					
						if (size_word > 1 ) begin
							read_addr <= read_addr - 1;
							state <= S1; end
						else if (m+1 <= num_blocks) begin
							t <= 0;
							state <= WRITE_PREP; end
						else begin
							read_signal <= 0;
							t <= 1;
							mem_write_data <= hash[0] + a;
							state <= S7; end
						end
				end
				
				2'b01: begin
					if (t <= 79) begin
						shift_array(sha1);
						{a, b, c, d, e} <= sha1_op(a, b, c, d, e, sha1, t);
						t <= t + 1;end
					else begin
						hash[0] <= hash[0] + a;
						hash[1] <= hash[1] + b;
						hash[2] <= hash[2] + c;
						hash[3] <= hash[3] + d;
						hash[4] <= hash[4] + e;
						size_word <= size_word + 1;
						m <= m + 1; 
					
						if (size_word > 1 ) begin
							read_addr <= read_addr - 1;
							state <= S1; end
						else if (m+1 <= num_blocks) begin
							t <= 0;
							state <= WRITE_PREP; end
						else begin
							read_signal <= 0;
							t <= 1;
							mem_write_data <= hash[0] + a;
							state <= S7; end
					end
				end
					
				default:begin
					if (t <= 63) begin
						shift_array(sha1);
						a <= t1_comp(e,f,g,h,sha1,t) + t2_comp(a,b,c) ;
						b <= a;
						c <= b;
						d <= c;
						e <= d + t1_comp(e,f,g,h,sha1,t);
						f <= e;
						g <= f;
						h <= g;
						t <= t + 1; end
					else begin
						hash[0] <= hash[0] + a;
						hash[1] <= hash[1] + b;
						hash[2] <= hash[2] + c;
						hash[3] <= hash[3] + d;
						hash[4] <= hash[4] + e;
						hash[5] <= hash[5] + f;
						hash[6] <= hash[6] + g;
						hash[7] <= hash[7] + h; 
						size_word <= size_word + 1;
						m <= m + 1; 
					
						if (size_word > 1 ) begin
							read_addr <= read_addr - 1;
							state <= S1; end
						else if (m+1 <= num_blocks) begin
							t <= 0;
							state <= WRITE_PREP; end
						else begin
							read_signal <= 0;
							t <= 1;
							mem_write_data <= hash[0] + a;
							state <= S7; end
					end
				end
			endcase
			end
			
			WRITE_PREP:
			begin
				case (opcode)
				2'b00: begin // md5
					a <= hash[0];
					b <= hash[1];
					c <= hash[2];
					d <= hash[3];
				end
				2'b01: begin // sha1
					a <= hash[0];
					b <= hash[1];
					c <= hash[2];
					d <= hash[3];
					e <= hash[4];
				end
				default: begin // sha256
					a <= hash[0];
					b <= hash[1];
					c <= hash[2];
					d <= hash[3];
					e <= hash[4];
					f <= hash[5];
					g <= hash[6];
					h <= hash[7];
				end
			endcase
				
				state <= S5;
			end

			
			S7:
			begin
			if(t < s7var) begin
			mem_write_data <= hash[t];
			write_addr <= write_addr + 1;
			t <= t + 1; 
			state <= S7; end
			else begin
			done <= 1;
			state <= IDLE; end
			end
		endcase	
	end
end


task data_padding;
	if ((size + 1) % 64 <= 56 && (size + 1) % 64 > 0)
        pad_length = (size/64)*64 + 56;
    else
        pad_length = (size/64+1)*64 + 56;
	num_blocks = (pad_length+8)/64;
endtask

task shift_array;
input [31:0] data;
begin
w[15] <= data;
w[14] <= w[15];
w[13] <= w[14];
w[12] <= w[13];
w[11] <= w[12];
w[10] <= w[11];
w[9] <= w[10];
w[8] <= w[9];
w[7] <= w[8];
w[6] <= w[7];
w[5] <= w[6];
w[4] <= w[5];
w[3] <= w[4];
w[2] <= w[3];
w[1] <= w[2];
w[0] <= w[1];
end
endtask

function [31:0] delimiter;
input [31:0] value;
case (size % 4)
	0: begin 
		delimiter = 32'h80000000; end 
	1: begin
		delimiter = value & 32'hFF000000 | 32'h00800000; end
	2: begin 
		delimiter = value & 32'hFFFF0000 | 32'h00008000; end
	3: begin 
		delimiter = value & 32'hFFFFFF00 | 32'h00000080; end
endcase
endfunction
endmodule