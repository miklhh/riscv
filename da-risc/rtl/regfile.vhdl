library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

package regfile_package is
    type regfile_port_type is array (natural range <>) of unsigned;
    type regfile_we_port_type is array(natural range <>) of std_logic;
end package regfile_package;

entity regfile is
    generic(
        XLEN        : integer := 32;
        READ_PORTS  : integer := 2;
        WRITE_PORTS : integer := 2
    );
    port(
        -- System wide signals
        clk_i  : std_logic;
        rst_ni : std_logic;

        -- Inputs:
        r_addr_i : regfile_port_type(0 to READ_PORTS-1)(4 downto 0);
        w_addr_i : regfile_port_type(0 to WRITE_PORTS-1)(4 downto 0);
        w_data_i : regfile_port_type(0 to WRITE_PORTS-1)(XLEN-1 downto 0);
        w_we     : regfile_we_port_type(0 to WRITE_PORTS-1);
        
        -- Outputs:
        r_data_o : regfile_port_type(0 to READ_PORTS-1)(XLEN-1 downto 0)
    );
end entity regfile;

architecture rtl of regfile is
    -- 32 registers
    signal reg : regfile_port_type(0 to 31)(XLEN-1 downto 0);
begin

    -- Register file write logic
    process(clk)
    begin
        if rising_edge(clk) then
            for w_port_idx in 0 to WRITE_PORTS-1 loop
                if w_we(w_port_idx) = '1' then
                    reg(to_integer(w_addr_i(w_port_idx))) <= w_data_i(w_port_idx);
                end if;
            end loop;
        end if;
    end process;

    -- Regfile read logic
    regfile_out : for r_port_idx in 0 to READ_PORTS-1 generate
        r_data_o(r_port_idx) <= reg(to_integer(r_addr_i(r_port_idx)));
    end generate;

end architecture;

