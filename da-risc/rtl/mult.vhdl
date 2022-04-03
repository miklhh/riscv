library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity alu is
    generic(
        XLEN : integer := 32
    );
    port(
        -- System wide signals
        clk_i  : std_logic;
        rst_ni : std_logic;

        -- Inputs:
        operand_a_i : signed(XLEN-1 downto 0);
        operand_b_i : signed(XLEN-1 downto 0);

        -- Outputs:
        alu_o : signed(XLEN-1 downto 0)
    );
end entity alu;

architecture rtl of alu is
begin

    -- Alu adder

    -- Output result mux with register
    process(clk)
    begin
        if rising_edge(clk) then
            case operator is
                when OP_ADD | OP_SUB =>
                    alu_o <= adder_res;
                when OP_AND =>
                    alu_o <= operand_a_i and operand_b_i;
                when OP_OR =>
                    alu_o <= operand_a_i or operand_b_i;
            end case;
        end if;
    end process;
end architecture;

