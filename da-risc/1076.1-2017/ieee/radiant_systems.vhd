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
--            : (RADIANT_SYSTEMS package declaration)
--
-- Library    : This package shall be compiled into a library symbolically 
--            : named IEEE.
--
-- Developers : IEEE DASC VHDL Multiple Energy Domain Packages Working Group
--            : IEEE P1076.1 Working Group
--
-- Purpose    : This package defines a set of types and natures that provide 
--            : a common framework for modeling radiant systems.
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
package RADIANT_SYSTEMS is

  -- subtype declarations
  subtype ILLUMINANCE        is REAL tolerance "DEFAULT_ILLUMINANCE";
  subtype LUMINOUS_FLUX      is REAL tolerance "DEFAULT_LUMINOUS_FLUX";
  subtype LUMINOUS_INTENSITY is REAL tolerance "DEFAULT_LUMINOUS_INTENSITY";
  subtype IRRADIANCE         is REAL tolerance "DEFAULT_IRRADIANCE";

  -- attribute declarations
  -- Use of UNIT to designate full description of units
  attribute UNIT   of ILLUMINANCE        : subtype is "lux";
  attribute UNIT   of LUMINOUS_FLUX      : subtype is "lumen";
  attribute UNIT   of LUMINOUS_INTENSITY : subtype is "candela";
  attribute UNIT   of IRRADIANCE         : subtype is "watt/meter^2";

  -- Use of SYMBOL to designate abbreviation of units
  attribute SYMBOL of ILLUMINANCE        : subtype is "lx";
  attribute SYMBOL of LUMINOUS_FLUX      : subtype is "lm";
  attribute SYMBOL of LUMINOUS_INTENSITY : subtype is "cd";
  attribute SYMBOL of IRRADIANCE         : subtype is "W/m^2";

  -- nature declarations
  nature RADIANT is
    LUMINOUS_INTENSITY across
    LUMINOUS_FLUX      through
    RADIANT_REF        reference;

  nature RADIANT_VECTOR is 
    array (NATURAL range <>) of RADIANT;

  -- vector subtype declarations
  subtype LUMINOUS_INTENSITY_VECTOR is RADIANT_VECTOR'across;
  subtype LUMINOUS_FLUX_VECTOR      is RADIANT_VECTOR'through;
  subtype ILLUMINANCE_VECTOR        is REAL_VECTOR tolerance
                                        "DEFAULT_ILLUMINANCE";
  subtype IRRADIANCE_VECTOR         is REAL_VECTOR tolerance 
                                        "DEFAULT_IRRADIANCE";

end package RADIANT_SYSTEMS;
