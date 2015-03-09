----------------------------------------------------------------------------------
-- Company: 
-- Engineer: 
-- 
-- Create Date: 03/06/2015 05:34:59 PM
-- Design Name: 
-- Module Name: Spec_Encrypt_Round - Behavioral
-- Project Name: 
-- Target Devices: 
-- Tool Versions: 
-- Description: 
-- 
-- Dependencies: 
-- 
-- Revision:
-- Revision 0.01 - File Created
-- Additional Comments:
-- 
----------------------------------------------------------------------------------


library IEEE;
use IEEE.STD_LOGIC_1164.ALL;

-- Uncomment the following library declaration if using
-- arithmetic functions with Signed or Unsigned values
use IEEE.NUMERIC_STD.ALL;

-- Uncomment the following library declaration if instantiating
-- any Xilinx leaf cells in this code.
--library UNISIM;
--use UNISIM.VComponents.all;

entity Spec_Encrypt_Round is
	 Generic( WORD_SIZE : integer := 15);
    Port ( KEY : in STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           B_IN : in STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           A_IN : in STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           B_OUT : out STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           A_OUT : out STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           SYS_CLK : in STD_LOGIC;
           RST : in STD_LOGIC);
end Spec_Encrypt_Round;

architecture Behavioral of Spec_Encrypt_Round is
signal key_buf : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal b_buf : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal a_buf : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal b_rotate : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal a_rotate : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal brt_a_sum : unsigned(WORD_SIZE downto 0);
signal new_b : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal new_a : STD_LOGIC_VECTOR(WORD_SIZE downto 0);

begin

--Async 
b_rotate <= (b_buf(7 downto 0) & b_buf(WORD_SIZE downto 8));
brt_a_sum <= unsigned(b_rotate) + unsigned(A_IN);
new_b <=  std_logic_vector(brt_a_sum) xor KEY;
a_rotate <= a_buf((WORD_SIZE -3) downto 0) & a_buf(WORD_SIZE downto (WORD_SIZE- 2));
new_a <= a_rotate xor new_b;

process(SYS_CLK)
begin
    if (SYS_CLK'event and SYS_CLK = '1') then
        if RST = '1' then
				key_buf <= (OTHERS => '0');
				b_buf <= (OTHERS => '0');
				a_buf <= (OTHERS => '0');
            B_OUT <= (OTHERS => '0');
            A_OUT <= (OTHERS => '0');
        else
				key_buf <= KEY;	
				b_buf <= B_IN;
				a_buf <= A_IN;
            B_OUT <= new_b; 
            A_OUT <= new_a;
        end if;
    end if;
end process;    


end Behavioral;
