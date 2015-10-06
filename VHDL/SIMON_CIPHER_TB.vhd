--------------------------------------------------------------------------------
-- Company: 
-- Engineer:
--
-- Create Date:   18:00:46 10/04/2015
-- Design Name:   
-- Module Name:   D:/Work/Code/Simon_Speck_Ciphers/VHDL/SIMON_CIPHER_TB.vhd
-- Project Name:  Simon
-- Target Device:  
-- Tool versions:  
-- Description:   
-- 
-- VHDL Test Bench Created by ISE for module: SIMON_CIPHER
-- 
-- Dependencies:
-- 
-- Revision:
-- Revision 0.01 - File Created
-- Additional Comments:
--
-- Notes: 
-- This testbench has been automatically generated using types std_logic and
-- std_logic_vector for the ports of the unit under test.  Xilinx recommends
-- that these types always be used for the top-level I/O of a design in order
-- to guarantee that the testbench will bind correctly to the post-implementation 
-- simulation model.
--------------------------------------------------------------------------------
LIBRARY ieee;
USE ieee.std_logic_1164.ALL;
 
-- Uncomment the following library declaration if using
-- arithmetic functions with Signed or Unsigned values
--USE ieee.numeric_std.ALL;
 
ENTITY SIMON_CIPHER_TB IS
END SIMON_CIPHER_TB;
 
ARCHITECTURE behavior OF SIMON_CIPHER_TB IS 
 
    -- Component Declaration for the Unit Under Test (UUT)
 
    COMPONENT SIMON_CIPHER
	 GENERIC(KEY_SIZE : integer range 0 to 256;
				BLOCK_SIZE : integer range 0 to 128;
				ROUND_LIMIT: integer range 0 to 72);
    PORT(
         SYS_CLK : IN  std_logic;
         RST : IN  std_logic;
         BUSY : OUT  std_logic;
         CONTROL : IN  std_logic_vector(1 downto 0);
         KEY : IN  std_logic_vector(255 downto 0);
         BLOCK_INPUT : IN  std_logic_vector(127 downto 0);
         BLOCK_OUTPUT : OUT  std_logic_vector(127 downto 0)
        );
    END COMPONENT;
    

   --Inputs
   signal SYS_CLK : std_logic := '0';
   signal RST : std_logic := '0';
   signal CONTROL : std_logic_vector(1 downto 0) := (others => '0');
   signal KEY : std_logic_vector(255 downto 0) := (others => '0');
   signal BLOCK_INPUT : std_logic_vector(127 downto 0) := (others => '0');

 	--Outputs
   signal BUSY : std_logic;
   signal BLOCK_OUTPUT : std_logic_vector(127 downto 0);

   -- Clock period definitions
   constant SYS_CLK_period : time := 10 ns;
 
BEGIN
 
	-- Instantiate the Unit Under Test (UUT)
   uut: SIMON_CIPHER
	GENERIC MAP (KEY_SIZE => 256,
					 BLOCK_SIZE => 128,
					 ROUND_LIMIT => 72)
	PORT MAP (
          SYS_CLK => SYS_CLK,
          RST => RST,
          BUSY => BUSY,
          CONTROL => CONTROL,
          KEY => KEY,
          BLOCK_INPUT => BLOCK_INPUT,
          BLOCK_OUTPUT => BLOCK_OUTPUT
        );

   -- Clock process definitions
   SYS_CLK_process :process
   begin
		SYS_CLK <= '0';
		wait for SYS_CLK_period/2;
		SYS_CLK <= '1';
		wait for SYS_CLK_period/2;
   end process;
 

   -- Stimulus process
   stim_proc: process
   begin		
      -- hold reset state for 100 ns.
      wait for 100 ns;	

      wait for SYS_CLK_period*10;
		
		KEY <= X"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
		CONTROL <= "01";
		wait for SYS_CLK_period*3;
		CONTROL <= "00";
		wait for SYS_CLK_period*100;
		
		BLOCK_INPUT <= X"74206e69206d6f6f6d69732061207369";
		CONTROL <= "11";
		wait for SYS_CLK_period*3;
		CONTROL <= "00";
		
		wait for SYS_CLK_period*100;
		
		BLOCK_INPUT <= X"8d2b5579afc8a3a03bf72a87efe7b868";
		CONTROL <= "10";
		wait for SYS_CLK_period*3;
		CONTROL <= "00";
		
		

      -- insert stimulus here 

      wait;
   end process;

END;
