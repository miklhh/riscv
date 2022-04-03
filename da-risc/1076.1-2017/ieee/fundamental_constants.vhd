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
--            : (FUNDAMENTAL_CONSTANTS package declaration)
--
-- Library    : This package shall be compiled into a library symbolically 
--            : named IEEE.

-- Developers : IEEE DASC VHDL Multiple Energy Domain Packages Working Group
--            : IEEE P1076.1 Working Group
--
-- Purpose    : This package defines a set of basic physical constants with 
--            : default values.
--
-- Limitation :
--
-- Notes      : The fundamental constants used in this package are based on
--            : the National Institute of Standards and Technology (NIST)
--            : values with published uncertainty as given in the table
--            : below:

-- Constant          Description           Default value      Uncertainty
-- --------          -----------           -------------      -----------
-- PHYS_Q            Electronic charge     1.602_176_462e-19  0.000_000_063e-19
-- PHYS_EPSO         Permittivity of       8.854_187_817e-12  exact
--                   vacuum
-- PHYS_MU0          Permeability of       4.0e-7*pi          exact
--                   vacuum
-- PHYS_K            Boltzmann’s constant  1.380_650_3e-23    0.000_002_4e-23
-- PHYS_GRAVITY      Acceleration due to   9.806_65           exact
--                   gravity
-- PHYS_CTOK         Convert degrees C->K  273.15             exact
-- PHYS_C            Velocity of light     299_792_458.0      exact
-- PHYS_H            Planck’s constant     6.626_068_76e-34   0.000_000_52e-34
-- PHYS_H_OVER_2_PI  Planck’s              PHYS_H/MATH_2_PI   0.000_000_82e-34
--                   constant/2*Pi
-- --------------------------------------------------------------------
-- Version : 3.0
-- Date : 03 February 2017
-- --------------------------------------------------------------------

library IEEE;
use IEEE.MATH_REAL.all;
package FUNDAMENTAL_CONSTANTS is

  -- Declaration
  attribute SYMBOL : STRING;
  attribute UNIT   : STRING;

  -- Physical Constant Definitions

  -- Electronic charge <COULOMB>
  constant PHYS_Q : REAL := 1.602_176_462e-19;

  -- Permittivity of vacuum <FARADS/METER>
  constant PHYS_EPS0 : REAL := 8.854_187_817e-12;

  -- Permeability of vacuum <HENRIES/METER>
  constant PHYS_MU0 : REAL := 4.0e-7 * MATH_PI;

  -- Boltzmann's constant <JOULES/KELVIN>
  constant PHYS_K : REAL := 1.380_650_3e-23;

  -- Acceleration due to gravity <METERS/SECOND_SQUARED>
  constant PHYS_GRAVITY : REAL := 9.806_65;

  -- Conversion between degrees Celsius and Kelvin
  constant PHYS_CTOK : REAL := 273.15;

  -- Velocity of light in a vacuum <METERS/SECOND>
  constant PHYS_C : REAL := 299_792_458.0;

  -- Planck’s constant
  constant PHYS_H : REAL := 6.626_068_76e-34;

  -- Planck’s constant divided by 2 pi
  constant PHYS_H_OVER_2_PI : REAL := PHYS_H/MATH_2_PI;

  -- common scaling factors
  constant  YOCTO  : REAL  := 1.0e-24;
  constant  ZEPTO  : REAL  := 1.0e-21;
  constant  ATTO   : REAL  := 1.0e-18;
  constant  FEMTO  : REAL  := 1.0e-15;
  constant  PICO   : REAL  := 1.0e-12;
  constant  NANO   : REAL  := 1.0e-9;
  constant  MICRO  : REAL  := 1.0e-6
  constant  MILLI  : REAL  := 1.0e-3;
  constant  CENTI  : REAL  := 1.0e-2;
  constant  DECI   : REAL  := 1.0e-1;
  constant  DEKA   : REAL  := 1.0e+1
  constant  HECTO  : REAL  := 1.0e+2;
  constant  KILO   : REAL  := 1.0e+3;
  constant  MEGA   : REAL  := 1.0e+6;
  constant  GIGA   : REAL  := 1.0e+9;
  constant  TERA   : REAL  := 1.0e+12;
  constant  PETA   : REAL  := 1.0e+15;
  constant  EXA    : REAL  := 1.0e+18;
  constant  ZETTA  : REAL  := 1.0e+21;
  constant  YOTTA  : REAL  := 1.0e+24;
  alias DECA is DEKA;

end package FUNDAMENTAL_CONSTANTS;
