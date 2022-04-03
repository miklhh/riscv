-----------------------------------------------------------------------
--
-- Copyright © 2005, 2010, 2017 by IEEE.
--
-- This source file is an essential part of IEEE Std 1076.1
-- IEEE Standard Analog and Mixed-Signal Extensions.
-- Verbatim copies of this source file may be used and distributed without
-- restriction. Modifications to this source file as permitted in IEEE Std
-- 1076.1-2017 may also be made and distributed. All other uses require
-- permission from the IEEE Standards Department(stds-ipr@ieee.org).
-- All other rights reserved.
--
-- This source file is provided on an AS IS basis. The IEEE disclaims ANY
-- WARRANTY EXPRESS OR IMPLIED INCLUDING ANY WARRANTY OF MERCHANTABILITY
-- AND FITNESS FOR USE FOR A PARTICULAR PURPOSE. The user of the source file
-- shall indemnify and hold IEEE harmless from any damages or liability
-- arising out of the use thereof.
--
-- Title      : Standard VHDL Analog and Mixed-Signal Extensions
--            : (THERMAL_SYSTEMS package declaration)
--
-- Library    : This package shall be compiled into a library symbolically 
--            : named IEEE.
--
-- Developers : IEEE DASC VHDL Multiple Energy Domain Packages Working Group
--            : IEEE P1076.1 Working Group
--
-- Purpose    : This package defines a set of types and natures that provide 
--            : a common framework for modeling thermal systems.
--
-- Limitation :
--
-- Notes      :
--
-- --------------------------------------------------------------------
-- Version : 3.0
-- Date : 03 February 2017
-- --------------------------------------------------------------------
library IEEE;
use IEEE.FUNDAMENTAL_CONSTANTS.all;
package THERMAL_SYSTEMS is

  -- subtype declarations
  subtype TEMPERATURE         is REAL tolerance "DEFAULT_TEMPERATURE";
  subtype HEAT_FLOW           is REAL tolerance "DEFAULT_HEAT_FLOW";
  subtype THERMAL_CAPACITANCE is REAL tolerance "DEFAULT_THERMAL_CAPACITANCE";
  subtype THERMAL_RESISTANCE  is REAL tolerance "DEFAULT_THERMAL_RESISTANCE";
  subtype THERMAL_CONDUCTANCE is REAL tolerance "DEFAULT_THERMAL_CONDUCTANCE";

  -- attribute declarations
  -- Use of UNIT to designate full description of units
  attribute UNIT   of TEMPERATURE         : subtype is "kelvin";
  attribute UNIT   of HEAT_FLOW           : subtype is "watt";
  attribute UNIT   of THERMAL_CAPACITANCE : subtype is "joule/kelvin";
  attribute UNIT   of THERMAL_RESISTANCE  : subtype is "kelvin/watt;
  attribute UNIT   of THERMAL_CONDUCTANCE : subtype is "watt/kelvin";

  -- Use of SYMBOL to designate abbreviation of units
  attribute SYMBOL of TEMPERATURE         : subtype is "K";
  attribute SYMBOL of HEAT_FLOW           : subtype is "W";
  attribute SYMBOL of THERMAL_CAPACITANCE : subtype is "J/K";
  attribute SYMBOL of THERMAL_RESISTANCE  : subtype is "K/W";
  attribute SYMBOL of THERMAL_CONDUCTANCE : subtype is "W/K";

  -- nature declarations
  nature THERMAL is
    TEMPERATURE across
    HEAT_FLOW   through
    THERMAL_REF reference;

  nature THERMAL_VECTOR is 
    array (NATURAL range <>) of THERMAL;

  -- vector subtype declarations
  subtype TEMPERATURE_VECTOR         is THERMAL_VECTOR'across;
  subtype HEAT_FLOW_VECTOR           is THERMAL_VECTOR'through;
  subtype THERMAL_CAPACITANCE_VECTOR is REAL_VECTOR tolerance
                                        "DEFAULT_THERMAL_CAPACITANCE";
  subtype THERMAL_RESISTANCE_VECTOR  is REAL_VECTOR tolerance
                                        "DEFAULT_THERMAL_RESISTANCE";
  subtype THERMAL_CONDUCTANCE_VECTOR is REAL_VECTOR tolerance
                                        "DEFAULT_THERMAL_CONDUCTANCE";

end package THERMAL_SYSTEMS;
