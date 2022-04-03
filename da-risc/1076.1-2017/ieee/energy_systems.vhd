----------------------------------------------------------------------
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
--            : (ENERGY_SYSTEMS package declaration)
--
-- Library    : This package shall be compiled into a library symbolically 
--            : named IEEE.
--
-- Developers : IEEE DASC VHDL Multiple Energy Domain Packages Working Group
--            : IEEE P1076.1 Working Group
--
-- Purpose    : This package defines a set of types and natures that provide 
--            : a common framework for modeling energy systems.
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
package ENERGY_SYSTEMS is

  -- subtype declarations
  subtype ENERGY        is REAL tolerance "DEFAULT_ENERGY";
  subtype POWER         is REAL tolerance "DEFAULT_POWER";
  subtype PERIODICITY   is REAL tolerance "DEFAULT_PERIODICITY";
  subtype REAL_ACROSS   is REAL tolerance "DEFAULT_REAL_ACROSS";
  subtype REAL_THROUGH  is REAL tolerance "DEFAULT_REAL_THROUGH";

  -- attribute declarations
  -- Use of UNIT to designate full description of units
  attribute UNIT   of ENERGY : subtype is "joule";
  attribute UNIT   of POWER  : subtype is "watt";

  -- Use of SYMBOL to designate abbreviation of units
  attribute SYMBOL of ENERGY : subtype is "J";
  attribute SYMBOL of POWER  : subtype is "W";

  -- nature declarations
  nature UNSPECIFIED is
    REAL_ACROSS     across
    REAL_THROUGH    through
    UNSPECIFIED_REF reference;

  nature UNSPECIFIED_VECTOR is
    array (NATURAL range <>) of UNSPECIFIED;

  -- vector subtype declarations
  subtype ENERGY_VECTOR       is REAL_VECTOR tolerance "DEFAULT_ENERGY";
  subtype POWER_VECTOR        is REAL_VECTOR tolerance "DEFAULT_POWER";
  subtype PERIODICITY_VECTOR  is REAL_VECTOR tolerance "DEFAULT_PERIODICITY";
  subtype REAL_ACROSS_VECTOR  is UNSPECIFIED_VECTOR'across;
  subtype REAL_THROUGH_VECTOR is UNSPECIFIED_VECTOR'through;

end package ENERGY_SYSTEMS;
