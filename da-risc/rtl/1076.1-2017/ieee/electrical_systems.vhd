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
--            : (ELECTRICAL_SYSTEMS package declaration)
--
-- Library    : This package shall be compiled into a library symbolically 
--            : named IEEE.
--
-- Developers : IEEE DASC VHDL Multiple Energy Domain Packages Working Group
--            : IEEE P1076.1 Working Group
--
-- Purpose    : This package defines a set of types and natures that provide 
--            : a common framework for modeling electrical, magnetic, and
--            : electromagnetic systems.
--
-- Limitation :
--
-- Notes      :
--
-- -------------------------------------------------------------------
-- Version : 3.0
-- Date : 03 February 2017
-- -------------------------------------------------------------------
library IEEE;
use IEEE.FUNDAMENTAL_CONSTANTS.all;
package ELECTRICAL_SYSTEMS is

  -- subtype declarations
  subtype VOLTAGE                 is REAL tolerance "DEFAULT_VOLTAGE";
  subtype CURRENT                 is REAL tolerance "DEFAULT_CURRENT";
  subtype CHARGE                  is REAL tolerance "DEFAULT_CHARGE";
  subtype RESISTANCE              is REAL tolerance "DEFAULT_RESISTANCE";
  subtype CONDUCTANCE             is REAL tolerance "DEFAULT_CONDUCTANCE";
  subtype CAPACITANCE             is REAL tolerance "DEFAULT_CAPACITANCE";
  subtype MMF                     is REAL tolerance "DEFAULT_MMF";
  subtype ELECTRIC_FLUX           is REAL tolerance "DEFAULT_FLUX";
  subtype ELECTRIC_FLUX_DENSITY   is REAL tolerance "DEFAULT_FLUX_DENSITY";
  subtype ELECTRIC_FIELD_STRENGTH is REAL tolerance "DEFAULT_FIELD_STRENGTH";
  subtype MAGNETIC_FLUX           is REAL tolerance "DEFAULT_FLUX";
  subtype MAGNETIC_FLUX_DENSITY   is REAL tolerance "DEFAULT_FLUX_DENSITY";
  subtype MAGNETIC_FIELD_STRENGTH is REAL tolerance "DEFAULT_FIELD_STRENGTH";
  subtype INDUCTANCE              is REAL tolerance "DEFAULT_INDUCTANCE";
  subtype RELUCTANCE              is REAL tolerance "DEFAULT_RELUCTANCE";

  -- attribute declarations
  -- Use of UNIT to designate full description of units
  attribute UNIT   of VOLTAGE                 : subtype is "volt";
  attribute UNIT   of CURRENT                 : subtype is "ampere";
  attribute UNIT   of CHARGE                  : subtype is "coulomb";
  attribute UNIT   of RESISTANCE              : subtype is "ohm";
  attribute UNIT   of CONDUCTANCE             : subtype is "siemens";
  attribute UNIT   of CAPACITANCE             : subtype is "farad";
  attribute UNIT   of MMF                     : subtype is "ampere";
  attribute UNIT   of ELECTRIC_FLUX           : subtype is "coulomb";
  attribute UNIT   of ELECTRIC_FLUX_DENSITY   : subtype is "coulomb/meter^2";
  attribute UNIT   of ELECTRIC_FIELD_STRENGTH : subtype is "volt/meter";
  attribute UNIT   of MAGNETIC_FLUX           : subtype is "weber";
  attribute UNIT   of MAGNETIC_FLUX_DENSITY   : subtype is "tesla";
  attribute UNIT   of MAGNETIC_FIELD_STRENGTH : subtype is "ampere/meter";
  attribute UNIT   of INDUCTANCE              : subtype is "henry";
  attribute UNIT   of RELUCTANCE              : subtype is "ampere/weber";

  -- Use of SYMBOL to designate abbreviation of units
  attribute SYMBOL of VOLTAGE                 : subtype is "V";
  attribute SYMBOL of CURRENT                 : subtype is "A";
  attribute SYMBOL of CHARGE                  : subtype is "C";
  attribute SYMBOL of RESISTANCE              : subtype is "Ohm";
  attribute SYMBOL of CONDUCTANCE             : subtype is "S";
  attribute SYMBOL of CAPACITANCE             : subtype is "F";
  attribute SYMBOL of MMF                     : subtype is "A";
  attribute SYMBOL of ELECTRIC_FLUX           : subtype is "C";
  attribute SYMBOL of ELECTRIC_FLUX_DENSITY   : subtype is "C/m^2";
  attribute SYMBOL of ELECTRIC_FIELD_STRENGTH : subtype is "V/m";
  attribute SYMBOL of MAGNETIC_FLUX           : subtype is "Wb";
  attribute SYMBOL of MAGNETIC_FLUX_DENSITY   : subtype is "T";
  attribute SYMBOL of MAGNETIC_FIELD_STRENGTH : subtype is "A/m";
  attribute SYMBOL of INDUCTANCE              : subtype is "H";
  attribute SYMBOL of RELUCTANCE              : subtype is "A/Wb";

  -- nature declarations
  nature ELECTRICAL is
    VOLTAGE        across
    CURRENT        through
    ELECTRICAL_REF reference;

  nature ELECTRICAL_VECTOR is 
    array (NATURAL range <>) of ELECTRICAL;

  nature MAGNETIC is
    MMF           across
    MAGNETIC_FLUX through
    MAGNETIC_REF  reference;

  nature MAGNETIC_VECTOR is 
    array (NATURAL range <>) of MAGNETIC;

  -- vector subtype declarations
  subtype VOLTAGE_VECTOR                 is ELECTRICAL_VECTOR'across;
  subtype CURRENT_VECTOR                 is ELECTRICAL_VECTOR'through;
  subtype MMF_VECTOR                     is MAGNETIC_VECTOR'across;
  subtype MAGNETIC_FLUX_VECTOR           is MAGNETIC_VECTOR'through;
  subtype CHARGE_VECTOR                  is REAL_VECTOR tolerance 
                                                "DEFAULT_CHARGE";
  subtype RESISTANCE_VECTOR              is REAL_VECTOR tolerance
                                                "DEFAULT_RESISTANCE";
  subtype CONDUCTANCE_VECTOR             is REAL_VECTOR tolerance
                                                "DEFAULT_CONDUCTANCE";
  subtype CAPACITANCE_VECTOR             is REAL_VECTOR tolerance
                                                "DEFAULT_CAPACITANCE";
  subtype ELECTRIC_FLUX_VECTOR           is REAL_VECTOR tolerance
                                                "DEFAULT_FLUX";
  subtype ELECTRIC_FLUX_DENSITY_VECTOR   is REAL_VECTOR tolerance
                                                "DEFAULT_FLUX_DENSITY";
  subtype ELECTRIC_FIELD_STRENGTH_VECTOR is REAL_VECTOR tolerance
                                                "DEFAULT_FIELD_STRENGTH";
  subtype MAGNETIC_FLUX_DENSITY_VECTOR   is REAL_VECTOR tolerance
                                                "DEFAULT_FLUX_DENSITY";
  subtype MAGNETIC_FIELD_STRENGTH_VECTOR is REAL_VECTOR tolerance
                                                "DEFAULT_FIELD_STRENGTH";
  subtype INDUCTANCE_VECTOR              is REAL_VECTOR tolerance
                                                "DEFAULT_INDUCTANCE";
  subtype RELUCTANCE_VECTOR              is REAL_VECTOR tolerance
                                                "DEFAULT_RELUCTANCE";

  alias GROUND is ELECTRICAL_REF;

end package ELECTRICAL_SYSTEMS;
