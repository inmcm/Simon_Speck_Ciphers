----------------------------------------------------------------------------------
-- Company: 
-- Engineer: 
-- 
-- Create Date:    11:16:40 03/08/2015 
-- Design Name: 
-- Module Name:    Simon_Encrypt_Round - Behavioral 
-- Project Name: 
-- Target Devices: 
-- Tool versions: 
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
--use IEEE.NUMERIC_STD.ALL;

-- Uncomment the following library declaration if instantiating
-- any Xilinx primitives in this code.
--library UNISIM;
--use UNISIM.VComponents.all;

entity Simon_Encrypt_Round is
    Generic( WORD_SIZE : integer := 63);
    Port ( KEY : in STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           B_IN : in STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           A_IN : in STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           B_OUT : out STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           A_OUT : out STD_LOGIC_VECTOR (WORD_SIZE downto 0);
           SYS_CLK : in STD_LOGIC;
           RST : in STD_LOGIC);
end Simon_Encrypt_Round;

architecture Behavioral of Simon_Encrypt_Round is

signal key_buf : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal b_buf : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal a_buf : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal new_a : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal b_lft1 : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal b_lft8 : STD_LOGIC_VECTOR(WORD_SIZE downto 0);
signal b_lft2 : STD_LOGIC_VECTOR(WORD_SIZE downto 0);

signal b_and : STD_LOGIC_VECTOR(WORD_SIZE downto 0);

signal b_xor : STD_LOGIC_VECTOR(WORD_SIZE downto 0);

signal a_xor : STD_LOGIC_VECTOR(WORD_SIZE downto 0);

signal key_xor : STD_LOGIC_VECTOR(WORD_SIZE downto 0);

signal new_b : STD_LOGIC_VECTOR(WORD_SIZE downto 0);


begin

--Async 
new_a <= b_buf;

b_lft1 <= b_buf((WORD_SIZE - 1) downto 0) & b_buf(WORD_SIZE);
b_lft8 <= b_buf((WORD_SIZE - 8) downto 0) & b_buf(WORD_SIZE downto (WORD_SIZE- 7));
b_lft2 <= b_buf((WORD_SIZE - 2) downto 0) & b_buf(WORD_SIZE downto (WORD_SIZE- 1));

b_and <= b_lft1 and b_lft8;

b_xor <= b_and xor b_lft2;

a_xor <= a_buf xor b_xor;

key_xor <= key_buf xor a_xor;

new_b <= key_xor;

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

