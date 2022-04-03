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
--            : (FLUIDIC_SYSTEMS package declaration)
--
-- Library    : This package shall be compiled into a library symbolically 
--            : named IEEE.
--
-- Developers : IEEE DASC VHDL Multiple Energy Domain Packages Working Group
--            : IEEE P1076.1 Working Group
--
-- Purpose    : This package defines a set of types and natures that provide
--            : a common framework for modeling fluidic systems.
--
-- Limitation :
--
-- Notes      : There are two natures in the fluidic systems package:
--            : FLUIDIC and COMPRESSIBLE_FLUIDIC.
--            : The FLUIDIC nature assumes a non-compressible medium and uses
--            : volume flow rate as the through variable.
--            : The COMPRESSIBLE_FLUIDIC nature assumes a potentially
--            : compressible medium and uses mass flow rate as the through
--            : variable.
--            : In both cases PRESSURE is used as the across variable.
--
-- --------------------------------------------------------------------
-- Version : 3.0
-- Date : 03 February 2017
-- --------------------------------------------------------------------
library IEEE;
use IEEE.FUNDAMENTAL_CONSTANTS.all;
package FLUIDIC_SYSTEMS is

  -- subtype declarations
  subtype PRESSURE       is REAL tolerance "DEFAULT_PRESSURE";
  subtype VFLOW_RATE     is REAL tolerance "DEFAULT_VFLOW_RATE";
  subtype MASS_FLOW_RATE is REAL tolerance "DEFAULT_MASS_FLOW_RATE";
  subtype VOLUME         is REAL tolerance "DEFAULT_VOLUME";
  subtype DENSITY        is REAL tolerance "DEFAULT_DENSITY";
  subtype VISCOSITY      is REAL tolerance "DEFAULT_VISCOSITY";
  subtype FRESISTANCE    is REAL tolerance "DEFAULT_FRESISTANCE";
  subtype FCONDUCTANCE   is REAL tolerance "DEFAULT_FCONDUCTANCE";
  subtype FCAPACITANCE   is REAL tolerance "DEFAULT_FCAPACITANCE";
  subtype INERTANCE      is REAL tolerance "DEFAULT_INERTANCE";
  subtype CFRESISTANCE   is REAL tolerance "DEFAULT_CFRESISTANCE";
  subtype CFCAPACITANCE  is REAL tolerance "DEFAULT_CFCAPACITANCE";
  subtype CFINERTANCE    is REAL tolerance "DEFAULT_CFINERTANCE";
  subtype CFCONDUCTANCE  is REAL tolerance "DEFAULT_CFCONDUCTANCE";

  -- attribute declarations
  -- Use of UNIT to designate full description of units
  attribute UNIT   of PRESSURE       : subtype is "pascal";
  attribute UNIT   of VFLOW_RATE     : subtype is "meter^3/second";
  attribute UNIT   of MASS_FLOW_RATE : subtype is "kilogram/second";
  attribute UNIT   of DENSITY        : subtype is "kilogram/meter^3";
  attribute UNIT   of VISCOSITY      : subtype is "pascal*second";
  attribute UNIT   of VOLUME         : subtype is "meter^3";
  attribute UNIT   of FRESISTANCE    : subtype is "pascal*second/meter^3";
  attribute UNIT   of FCONDUCTANCE   : subtype is "meter^3/(pascal*second)";
  attribute UNIT   of FCAPACITANCE   : subtype is "meter^3/pascal";
  attribute UNIT   of INERTANCE      : subtype is "pascal*second^2/meter^3";
  attribute UNIT   of CFRESISTANCE   : subtype is "pascal*second/kilogram";
  attribute UNIT   of CFCAPACITANCE  : subtype is "kilogram/pascal";
  attribute UNIT   of CFINERTANCE    : subtype is "pascal*second^2/kilogram";
  attribute UNIT   of CFCONDUCTANCE  : subtype is "kilogram/(pascal*second)";

  -- Use of SYMBOL to designate abbreviation of units
  attribute SYMBOL of PRESSURE       : subtype is "Pa";
  attribute SYMBOL of VFLOW_RATE     : subtype is "m^3/s";
  attribute SYMBOL of MASS_FLOW_RATE : subtype is "kg/s";
  attribute SYMBOL of DENSITY        : subtype is "kg/m^3";
  attribute SYMBOL of VISCOSITY      : subtype is "Pa*s";
  attribute SYMBOL of VOLUME         : subtype is "m^3";
  attribute SYMBOL of FRESISTANCE    : subtype is "Pa*s/m^3";
  attribute SYMBOL of FCONDUCTANCE   : subtype is "m^3/(Pa*s)";
  attribute SYMBOL of FCAPACITANCE   : subtype is "m^3/Pa";
  attribute SYMBOL of INERTANCE      : subtype is "Pa*s^2/m^3";
  attribute SYMBOL of CFRESISTANCE   : subtype is "Pa*s/kg";
  attribute SYMBOL of CFCAPACITANCE  : subtype is "kg/Pa";
  attribute SYMBOL of CFINERTANCE    : subtype is "Pa*s^2/kg";
  attribute SYMBOL of CFCONDUCTANCE  : subtype is "kg/(Pa*s)";

  -- nature declarations
  nature FLUIDIC is
    PRESSURE    across
    VFLOW_RATE  through
    FLUIDIC_REF reference;

  nature FLUIDIC_VECTOR is 
    array (NATURAL range <>) of FLUIDIC;

  nature COMPRESSIBLE_FLUIDIC is
    PRESSURE                 across
    MASS_FLOW_RATE           through
    COMPRESSIBLE_FLUIDIC_REF reference;

  nature COMPRESSIBLE_FLUIDIC_VECTOR is 
    array (NATURAL range <>) of COMPRESSIBLE_FLUIDIC;

  -- vector subtype declarations
  subtype PRESSURE_VECTOR       is FLUIDIC_VECTOR'across;
  subtype VFLOW_RATE_VECTOR     is FLUIDIC_VECTOR'through;
  subtype MASS_FLOW_RATE_VECTOR is COMPRESSIBLE_FLUIDIC_VECTOR'through;
  subtype VOLUME_VECTOR         is REAL_VECTOR tolerance "DEFAULT_VOLUME";
  subtype DENSITY_VECTOR        is REAL_VECTOR tolerance "DEFAULT_DENSITY";
  subtype VISCOSITY_VECTOR      is REAL_VECTOR tolerance "DEFAULT_VISCOSITY";
  subtype FRESISTANCE_VECTOR    is REAL_VECTOR tolerance "DEFAULT_FRESISTANCE";
  subtype FCONDUCTANCE_VECTOR   is REAL_VECTOR tolerance "DEFAULT_FCONDUCTANCE";
  subtype FCAPACITANCE_VECTOR   is REAL_VECTOR tolerance "DEFAULT_FCAPACITANCE";
  subtype INERTANCE_VECTOR      is REAL_VECTOR tolerance "DEFAULT_INERTANCE";
  subtype CFRESISTANCE_VECTOR   is REAL_VECTOR tolerance "DEFAULT_CFRESISTANCE";
  subtype CFCONDUCTANCE_VECTOR  is REAL_VECTOR tolerance "DEFAULT_CFCONDUCTANCE";
  subtype CFCAPACITANCE_VECTOR  is REAL_VECTOR tolerance "DEFAULT_CFCAPACITANCE";
  subtype CFINERTANCE_VECTOR    is REAL_VECTOR tolerance "DEFAULT_CFINERTANCE";

end package FLUIDIC_SYSTEMS;
