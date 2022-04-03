-----------------------------------------------------------------------
--
-- Copyright © 2005, 2010, 2017 by IEEE.
--
-- This source file is an informative part of IEEE Std 1076.1
-- IEEE Standard VHDL Analog and Mixed-Signal Extensions. 
-- Copies of this source file may be used and distributed without restriction. 
-- Modifications to this source file to reflect the manufacturing and
-- physical environment are permitted without restrictions.
--
-- This source file is provided on an AS IS basis. The IEEE disclaims ANY
-- WARRANTY EXPRESS OR IMPLIED INCLUDING ANY WARRANTY OF MERCHANTABILITY
-- AND FITNESS FOR USE FOR A PARTICULAR PURPOSE. The user of the source file
-- shall indemnify and hold IEEE harmless from any damages or liability
-- arising out of the use thereof.
--
-- Title      : Standard VHDL Analog and Mixed-Signal Extensions
--            : (MATERIAL_CONSTANTS package body)
--
-- Library    : This package body shall be compiled into a library
--            : symbolically named IEEE_ENV.
--
-- Developers : IEEE DASC VHDL Multiple Energy Domain Packages Working Group
--            : IEEE P1076.1 Working Group 
--
-- Purpose    : This package body defines commonly used values for basic 
--            : physical constants related to material properties and 
--            : environmental context.
--
-- Limitation :
--
-- Notes      : Deferred constants are used to allow users to define the 
--            : values of material properties and environmental context.
--            : This flexibility is necessary to reflect that these values
--            : are measured, which makes them subject to variation according 
--            : to the application context, environmental conditions, and
--            : assumptions of individual experiments.
--
--            : The values of the constants in this package body are typical
--            : for many situations. They are based on values published by
--            : [1] the National Institute of Standards and Technology (NIST)
--            : [2] John Lau, "Thermal Stress and Strain in Microelectronics 
--            :     Packaging"
-- --------------------------------------------------------------------
-- Version : 3.0
-- Date : 03 February 2017
-- --------------------------------------------------------------------
package body MATERIAL_CONSTANTS is

  -- Relative permittivity of silicon [1]
  constant PHYS_EPS_SI : REAL := 11.7;

  -- Relative permittivity of silicon dioxide [1]
  constant PHYS_EPS_SIO2 : REAL := 3.9;

  -- Young's Modulus for silicon [1] <PASCALS>
  constant PHYS_E_SI : REAL := 190.0e+9;

  -- Young's Modulus for silicon dioxide [1] <PASCALS>
  constant PHYS_E_SIO2 : REAL := 73.0e+9;

  -- Young's Modulus for polysilicon [2] <PASCALS>
  constant PHYS_E_POLY : REAL := 1.62e+9;

  -- Poisson's Ratio for silicon [1] <100-orientation>
  constant PHYS_NU_SI : REAL := 0.28;

  -- Poisson's Ratio for polysilicon [2] <100-orientation>
  constant PHYS_NU_POLY : REAL := 0.22;

  -- Density of polysilicon [1] <KILOGRAMS/METER_CUBED>
  constant PHYS_RHO_POLY : REAL := 2330.0;

  -- Density of silicon-dioxide [2] <KILOGRAMS/METER_CUBED>
  constant PHYS_RHO_SIO2 : REAL := 2220.0;

  -- Environmental constants
  -- Ambient temperature <KELVIN>
  constant AMBIENT_TEMPERATURE : REAL := 298.15;

  -- Ambient pressure [1] <PASCALS>
  constant AMBIENT_PRESSURE : REAL := 100_000.0;

  -- Ambient illuminance [1] <LUX>
  constant AMBIENT_ILLUMINANCE : REAL := 30_000.0; -- value for daylight

end package body MATERIAL_CONSTANTS;

