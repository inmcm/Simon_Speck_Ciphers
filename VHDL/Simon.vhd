library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC.ALL;

entity SIMON_CIPHER is
	Generic(KEY_SIZE : integer range 0 to 256;
			BLOCK_SIZE : integer range 0 to 128);
    
    Port (SYS_CLK,RST : in std_logic;
    		BUSY : out  std_logic;
    		CONTROL : in  std_logic_vector(2 downto 0);
    		KEY : in  std_logic_vector (KEY_SIZE - 1 downto 0)
			BLOCK_INPUT : in  std_logic_vector (BLOCK_SIZE - 1 downto 0);
			BLOCK_OUTPUT : out  std_logic_vector (BLOCK_SIZE - 1 downto 0));
			
end SIMON_CIPHER;


architecture Behavioral of AES_128_ENCRYPT is
-------------------------------------------------------------
-- Cipher Constants
constant WORD_SIZE : integer range 0 to 64 := BLOCK_SIZE / 2;
constant K_SEGMENTS : integer range 0 to 4 := KEY_SIZE /  WORD_SIZE

constant ROUND_CONSTANT_HI std_logic_vector(WORD_SIZE - 5 downto 0) := (OTHERS => '1'); 
constant ROUND_CONSTANT_LO std_logic_vector(3 downto 0) := X"C";
constant ALL_ZEROS std_logic_vector(WORD_SIZE - 1 downto 0) := (OTHERS => '0');
-------------------------------------------------------------



----------------------------------
-- Round Limit and Z Array Assignments
-- Assigned by Block Size and Key Size as Given in Specification
----------------------------------

-- Block Size 32 and Key Size 64 use z0 and 32 rounds
if (BLOCK_SIZE = 32 and KEY_SIZE = 64) generate
	constant ZJ : std_logic_vector(61 downto 0) = "01100111000011010100100010111110110011100001101010010001011111";
	constant ROUND_LIMIT : integer range 0 to 72 = 32;
end generate;


-- Block Size 48 and Key Size 72 use z0 and 36 rounds
if (BLOCK_SIZE = 48 and KEY_SIZE = 72) generate
	constant ZJ : std_logic_vector(61 downto 0) = "01100111000011010100100010111110110011100001101010010001011111";
	constant ROUND_LIMIT : integer range 0 to 72 = 36;
end generate;


-- Block Size 48 and Key Size 96 use z1 and 36 rounds
if (BLOCK_SIZE = 48 and KEY_SIZE = 96) generate
	constant ZJ : std_logic_vector(61 downto 0) = "01011010000110010011111011100010101101000011001001111101110001";
	constant ROUND_LIMIT : integer range 0 to 72 = 36;
end generate;


-- Block Size 64 and Key Size 96 use z2 and 42 rounds
if (BLOCK_SIZE = 64 and KEY_SIZE = 96 ) generate
	constant ZJ : std_logic_vector(61 downto 0) = "11001101101001111110001000010100011001001011000000111011110101";
	constant ROUND_LIMIT : integer range 0 to 72 = 42;
end generate;


-- Block Size 64 and Key Size 128 use z3 and 44 rounds
if (BLOCK_SIZE = 64 and KEY_SIZE = 128) generate
	constant ZJ : std_logic_vector(61 downto 0) = "11110000101100111001010001001000000111101001100011010111011011";
	constant ROUND_LIMIT : integer range 0 to 72 = 44;
end generate;


-- Block Size 96 and Key Size 96  use z2 and 52 rounds
if (BLOCK_SIZE = 96 and KEY_SIZE = 96) generate
	constant ZJ : std_logic_vector(61 downto 0) = "11001101101001111110001000010100011001001011000000111011110101";
	constant ROUND_LIMIT : integer range 0 to 72 = 52;
end generate;


-- Block Size 96 and Key Size 144 use z3 and 54 rounds
if (BLOCK_SIZE =  and KEY_SIZE = ) generate
	constant ZJ : std_logic_vector(61 downto 0) = "11110000101100111001010001001000000111101001100011010111011011";
	constant ROUND_LIMIT : integer range 0 to 72 = 54;
end generate;


-- Block Size 128 and Key Size 128 use z2 and 68 rounds 
if (BLOCK_SIZE = 128 and KEY_SIZE = 128) generate
	constant ZJ : std_logic_vector(61 downto 0) = "11001101101001111110001000010100011001001011000000111011110101";
	constant ROUND_LIMIT : integer range 0 to 72 = 68;
end generate;


-- Block Size 128 and Key Size 192 use z3  and 69 rounds
if (BLOCK_SIZE = 128 and KEY_SIZE = 192) generate
	constant ZJ : std_logic_vector(61 downto 0) = "11110000101100111001010001001000000111101001100011010111011011";
	constant ROUND_LIMIT : integer range 0 to 72 = 69;
end generate;


-- Block Size 128 and Key Size 256 use z4 and 72 rounds
if (BLOCK_SIZE = 128 and KEY_SIZE = 256) generate
	constant ZJ : std_logic_vector(61 downto 0) = "11110111001001010011000011101000000100011011010110011110001011";
	constant ROUND_LIMIT : integer range 0 to 72 = 72;
end generate;

-- Key Schedule Storage Array
type ARRAY_ROUNDxWORDSIZE is array(0 to ROUND_LIMIT - 1) of std_logic_vector(WORD_SIZE - 1 downto 0);
type INV_ARRAY_ROUNDxWORDSIZE is array(ROUND_LIMIT - 1 downto 0) of std_logic_vector(WORD_SIZE - 1 downto 0);
signal key_schedule: ARRAY_ROUNDxWORDSIZE;

alias inv_key_schedule : INV_ARRAY_ROUNDxWORDSIZE
	is key_schedule;

-- or i above fails
--signal inv_key_schedule : ARRAY_ROUNDxWORDSIZE
--Map_Inverse_Key_Schedule : for i in 0 to ROUND_LIMIT - 1 generate
--	inv_key_schedule(i) <= key_schedule((ROUND_LIMIT - 1) - i);
--end generate ; -- Map_Inverse_Key_Schedule

signal round_constant : std_logic_vector(WORD_SIZE - 1 downto 0);

-- Storage Bit for which direction the cipher is opperating in:
-- 0 - Encryption
-- 1 - Decryption
signal cipher_direction : std_logic := 0;

type ARRAY_PARTKEYxWORD is array (0 to K-1) of std_logic_vector(WORD_SIZE - 1 downto 0);
signal key_gen : ARRAY_PARTKEYxWORD;

------------------------------------------------------
-- Fiestel Structure Signals
signal key_buf : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);
signal b_buf : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);
signal a_buf : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);
signal b_lft1 : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);
signal b_lft8 : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);
signal b_lft2 : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);

signal b_and : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);

signal b_xor : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);

signal a_xor : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);

signal key_xor : STD_LOGIC_VECTOR(WORD_SIZE - 1 downto 0);

--------------------------------------------------------

type state is (Reset, Idle, Key_Schedule_Generation, Run_Cipher, Encryption_Latch, Decryption_Latch);
signal pr_state,nx_state : state;

begin

----------------------------------------------------------------------
-- State Machine Processes
----------------------------------------------------------------------
State_Machine_Head : process (SYS_CLK) ----State Machine Master Control
begin
	if (SYS_CLK'event and SYS_CLK='1') then
		if (RST = '1') then
			pr_state <= RESET;
		else
			pr_state <= nx_state;
		end if;
	end if;
end process; -- State_Machine_Head

State_Machine_Body : process (CONTROL, round_count, cipher_direction, pr_state) ---State Machine State Definitions
begin
	case pr_state is
		
		when Reset =>  --Master Reset State
			nx_state <= Idle;

		when Idle =>  
			if (CONTROL = "01") then
				nx_state <= Key_Schedule_Generation;
			elsif (CONTROL = '10' or ONTROL = '11') then
				nx_state <= Run_Cipher;
			else
				nx_state <= IDLE;
			end if;	

		when Key_Schedule_Generation =>  
			if (round_count = ROUND_LIMIT) then
				nx_state <= Idle;
			else
				nx_state <= Key_Schedule_Generation;
			end if;	

		when Run_Cipher =>  
			if (round_count = ROUND_LIMIT) then
				if (cipher_direction = '0') then
					nx_state <= Encryption_Latch;
				else
					nx_state <= Decryption_Latch;
				end if ;
			else
				nx_state <= Run_Cipher;
			end if;	

		when Encryption_Latch =>
			nx_state <= Idle;

		when Decryption_Latch =>
			nx_state <= Idle;

	end case;
end process;

----------------------------------------------------------------------
-- END State Machine Processes
----------------------------------------------------------------------



----------------------------------------------------------------------
-- Register Processes
----------------------------------------------------------------------

Cipher_Direction_Buffer : process(SYS_CLK)
begin
	if SYS_CLK'event and SYS_CLK = 1 then
		if (pr_state = Idle) then
			cipher_direction <= CONTROL(0);
		end if;
	end if;	
end process ; -- Cipher_Direction_Buffer


Busy_Flag_Generator : process(SYS_CLK)
begin
	if SYS_CLK'event and SYS_CLK = 1 then
		if (pr_state = Key_Schedule_Generation or pr_state = Run_Cipher) then
			BUSY <= '1';
		else
			BUSY <= '0';
		end if;
	end if;	
end process ; -- Busy_Flag_Generator


Key_Schedule_Generator : process(SYS_CLK)
begin
	if SYS_CLK'event and SYS_CLK = 1 then
		if (pr_state = Idle) then
			Init_Gen_Regs : for i in 0 to (K-1) loop
				key_gen(i) <= key(i+1);
			end loop ; -- Update_Gen_Regs

		elsif (pr_state = Key_Schedule_Generation) then
			-- Store new entry in key schedule array
			key_schedule(round_count) <= key_gen(0);
			
			Key_Feedback_1 : if (k != 4) generate
				key_gen(K-1) <= key_gen(0)	^ s3 ^ s4 ^ z_ji ^ round_constant;
			end generate;

			Key_Feedback_2 : if (k = 4) generate
				key_gen(K-1) <= key_gen(0) ^ key_gen(1)	^ s3 ^ s4 ^ z_ji ^ round_constant;
			end generate;

			Update_Gen_Regs : for i in 0 to (K-2) loop
				key_gen(i) <= key_gen(i+1);
			end loop ; -- Update_Gen_Regs
		
		end if;
	end if;
end process ; -- Key_Schedule_Generator


Fiestel_Round : process(SYS_CLK)
begin
	if SYS_CLK'event and SYS_CLK = 1 then
		if (pr_state = Idle) then
			if (CONTROL = '10') then
				a_buf = BLOCK_INPUT(WORD_SIZE - 1 downto 0);
				b_buf = BLOCK_INPUT(BLOCK_SIZE - 1 downto WORD_SIZE);
			elsif (CONTROL = '11') then
				a_buf = BLOCK_INPUT(BLOCK_SIZE - 1 downto WORD_SIZE);
				b_buf = BLOCK_INPUT(WORD_SIZE - 1 downto 0);
			end if;
		elsif (pr_state = Run_Cipher) then
			a_buf <= new_b;
			b_buf <= a_buf;
		end if;
	end if;
end process ; -- Fiestel_Round


Output_Buffer : process(SYS_CLK)
begin
	if SYS_CLK'event and SYS_CLK = 1 then
		if (pr_state = Encryption_Latch) then
			BLOCK_OUTPUT <= b_buf & a_buf;
		elsif (pr_state = Decryption_Latch) then
			BLOCK_OUTPUT <= a_buf & b_buf;
		end if;
	end if;
end process ; -- Output_Buffer

----------------------------------------------------------------------
-- END Register Processes
----------------------------------------------------------------------



----------------------------------------------------------------------
-- Counter Processes
----------------------------------------------------------------------
	
Round_Counter : process(SYS_CLK)
begin
	if (SYS_CLK'event and SYS_CLK = 1) then
		if pr_state = Reset or pr_state = Idle then
			round_count = 0;
		elsif (pr_state = Run_Cipher or pr_state = Generate_Key_Schedule) then
			round_count = round_count + 1;
		end if ;
	end if ;
end process;
	
----------------------------------------------------------------------
-- END Counter Processes
----------------------------------------------------------------------


----------------------------------------------------------------------
-- Async Signals
----------------------------------------------------------------------

-- Fiestel Round
b_lft1 <= b_buf((WORD_SIZE - 2) downto 0) & b_buf(WORD_SIZE - 1);
b_lft8 <= b_buf((WORD_SIZE - 9) downto 0) & b_buf(WORD_SIZE - 1 downto (WORD_SIZE- 8));
b_lft2 <= b_buf((WORD_SIZE - 3) downto 0) & b_buf(WORD_SIZE - 1 downto (WORD_SIZE- 2));

b_and <= b_lft1 and b_lft8;

b_xor <= b_and xor b_lft2;

a_xor <= a_buf xor b_xor;

with cipher_direction select key_buf <=
	key_schedule(round_count) when "0",
	inv_key_schedule(round_count) when "1";

key_xor <= key_buf xor a_xor;


-- Key Schedule Generation Logic
s3 <= key_gen(0)(2 downto 0) & key_gen(0)(WORD_SIZE - 1 downto 3);
s4 <= key_gen(0)(3 downto 0) & key_gen(0)(WORD_SIZE - 1 downto 4);
round_constant <= ROUND_CONSTANT_HI & ROUND_CONSTANT_LO;
zji <= ALL_ZEROS(WORD_SIZE - 1 downto 1) & zj(round_count mod 62);

----------------------------------------------------------------------
-- END Async Signals
----------------------------------------------------------------------

end Behavioral;

	
