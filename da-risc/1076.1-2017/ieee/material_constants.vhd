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
--            : (MATERIAL_CONSTANTS package declaration)
--
-- Library    : This package shall be compiled into a library symbolically 
--            : named IEEE_ENV.
--
-- Developers : IEEE DASC VHDL Multiple Energy Domain Packages Working Group
--            : IEEE P1076.1 Working Group
--
-- Purpose    : This package defines a set of basic physical constants. Their 
--            : default values can be defined by the user.
--
-- Limitation :
--
-- Notes      : Deferred constants allow the user to define the value, but
--            : the names of these constants have been standardized. The
--            : rationale for this is that, for example, properties of
--            : materials are measured and subject to variation according the
--            : application context, environmental conditions, and
--            : assumptions of individual experiments.
--            :
--            : The values of the constants used in this package were based
--            : on the National Institute of Standards and Technology (NIST)
--            : values (or from reference [1] given below) provided in the
--            : table below:
--
-- Constant       Typical Value  Description
-- --------       -------------  -----------
-- PHYS_EPS_SI    11.7           Relative permittivity of silicon
-- PHYS_EPS_SIO2  3.9            Relative permittivity of silicon dioxide
-- PHYS_E_SI      190.0e+9       Young's Modulus for silicon <PASCALS>
-- PHYS_E_SIO2    73.0e+9        Young's Modulus for silicon dioxide <PASCALS>
-- PHYS_E_POLY    1.62e+9 [1]    Young's Modulus for polysilicon <PASCALS>
-- PHYS_NU_SI     0.28           Poisson's Ratio for silicon <100-orientation>
-- PHYS_NU_POLY   0.22    [1]    Poisson's Ratio for polysilicon <100-orientation>
-- PHYS_RHO_POLY  2330           Density of polysilicon <KILOGRAMS/METER_CUBED>
-- PHYS_RHO_SIO2  2220    [1]    Density of silicon-dioxide <KILOGRAMS/METER_CUBED>
--
-- [1] John Lau, "Thermal Stress and Strain in Microelectronics Packaging"
--
-- --------------------------------------------------------------------
-- Version : 3.0
-- Date : 03 February 2017
-- --------------------------------------------------------------------
package MATERIAL_CONSTANTS is

  -- Relative permittivity of silicon
  constant PHYS_EPS_SI : REAL;

  -- Relative permittivity of silicon dioxide
  constant PHYS_EPS_SIO2 : REAL;

  -- Young's Modulus for silicon <PASCALS>
  constant PHYS_E_SI : REAL;

  -- Young's Modulus for silicon dioxide <PASCALS>
  constant PHYS_E_SIO2 : REAL;

  -- Young's Modulus for polysilicon <PASCALS>
  constant PHYS_E_POLY : REAL;

  -- Poisson's Ratio for silicon <100-orientation>
  constant PHYS_NU_SI : REAL;

  -- Poisson's Ratio for polysilicon <100-orientation>
  constant PHYS_NU_POLY : REAL;

  -- Density of polysilicon < KILOGRAMS/METER_CUBED>
  constant PHYS_RHO_POLY : REAL;

  -- Density of silicon-dioxide <KILOGRAMS/METER_CUBED>
  constant PHYS_RHO_SIO2 : REAL;

  -- Environmental constants
  constant AMBIENT_TEMPERATURE : REAL; -- Ambient temperature <KELVIN>
  constant AMBIENT_PRESSURE    : REAL; -- Ambient pressure <PASCALS>
  constant AMBIENT_ILLUMINANCE : REAL; -- Ambient illuminance <LUX>

end package MATERIAL_CONSTANTS;
