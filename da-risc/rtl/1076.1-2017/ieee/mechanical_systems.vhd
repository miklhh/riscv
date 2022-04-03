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
--            : (MECHANICAL_SYSTEMS package declaration)
--
-- Library    : This package shall be compiled into a library symbolically 
--            : named IEEE.
--
-- Developers : IEEE DASC VHDL Multiple Energy Domain Packages Working Group
--            : IEEE P1076.1 Working Group
--
-- Purpose    : This package defines a set of types and natures that provide 
--            : a common framework for modeling mechanical systems.
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
package MECHANICAL_SYSTEMS is

  -- subtype declarations
  subtype DISPLACEMENT         is REAL tolerance "DEFAULT_DISPLACEMENT";
  subtype FORCE                is REAL tolerance "DEFAULT_FORCE";
  subtype VELOCITY             is REAL tolerance "DEFAULT_VELOCITY";
  subtype ACCELERATION         is REAL tolerance "DEFAULT_ACCELERATION";
  subtype MASS                 is REAL tolerance "DEFAULT_MASS";
  subtype STIFFNESS            is REAL tolerance "DEFAULT_STIFFNESS";
  subtype DAMPING              is REAL tolerance "DEFAULT_DAMPING";
  subtype MOMENTUM             is REAL tolerance "DEFAULT_MOMENTUM";
  subtype ANGLE                is REAL tolerance "DEFAULT_ANGLE";
  subtype TORQUE               is REAL tolerance "DEFAULT_TORQUE";
  subtype ANGULAR_VELOCITY     is REAL tolerance "DEFAULT_ANGULAR_VELOCITY";
  subtype ANGULAR_ACCELERATION is REAL tolerance "DEFAULT_ANGULAR_ACCELERATION";
  subtype MOMENT_INERTIA       is REAL tolerance "DEFAULT_MOMENT_INERTIA";
  subtype ANGULAR_MOMENTUM     is REAL tolerance "DEFAULT_ANGULAR_MOMENTUM";
  subtype ANGULAR_STIFFNESS    is REAL tolerance "DEFAULT_ANGULAR_STIFFNESS";
  subtype ANGULAR_DAMPING      is REAL tolerance "DEFAULT_ANGULAR_DAMPING";

  -- attribute declarations
  -- Use of UNIT to designate full description of units
  attribute UNIT   of DISPLACEMENT         : subtype is "meter";
  attribute UNIT   of FORCE                : subtype is "newton";
  attribute UNIT   of VELOCITY             : subtype is "meter/second";
  attribute UNIT   of ACCELERATION         : subtype is "meter/second^2";
  attribute UNIT   of MASS                 : subtype is "kilogram";
  attribute UNIT   of STIFFNESS            : subtype is "newton/meter";
  attribute UNIT   of DAMPING              : subtype is "newton*second/meter";
  attribute UNIT   of MOMENTUM             : subtype is "kilogram*meter/second";
  attribute UNIT   of ANGLE                : subtype is "radian";
  attribute UNIT   of TORQUE               : subtype is "newton*meter";
  attribute UNIT   of ANGULAR_VELOCITY     : subtype is "radian/second";
  attribute UNIT   of ANGULAR_ACCELERATION : subtype is "radian/second^2";
  attribute UNIT   of MOMENT_INERTIA       : subtype is "kilogram*meter^2";
  attribute UNIT   of ANGULAR_MOMENTUM     : subtype is "kilogram*meter^2/second";
  attribute UNIT   of ANGULAR_STIFFNESS    : subtype is "newton*meter/radian";
  attribute UNIT   of ANGULAR_DAMPING      : subtype is "newton*meter*second/radian";

  -- Use of SYMBOL to designate abbreviations of units
  attribute SYMBOL of DISPLACEMENT         : subtype is "m";
  attribute SYMBOL of FORCE                : subtype is "N";
  attribute SYMBOL of VELOCITY             : subtype is "m/s";
  attribute SYMBOL of ACCELERATION         : subtype is "m/s^2";
  attribute SYMBOL of MASS                 : subtype is "kg";
  attribute SYMBOL of STIFFNESS            : subtype is "N/m";
  attribute SYMBOL of DAMPING              : subtype is "N*s/m";
  attribute SYMBOL of MOMENTUM             : subtype is "kg*m/s";
  attribute SYMBOL of ANGLE                : subtype is "rad";
  attribute SYMBOL of TORQUE               : subtype is "N*m";
  attribute SYMBOL of ANGULAR_VELOCITY     : subtype is "rad/s";
  attribute SYMBOL of ANGULAR_ACCELERATION : subtype is "rad/s^2";
  attribute SYMBOL of MOMENT_INERTIA       : subtype is "kg*m^2";
  attribute SYMBOL of ANGULAR_MOMENTUM     : subtype is "kg*m^2/s";
  attribute SYMBOL of ANGULAR_STIFFNESS    : subtype is "N*m/rad";
  attribute SYMBOL of ANGULAR_DAMPING      : subtype is "N*m*s/rad";

  -- nature declarations
  nature TRANSLATIONAL is
    DISPLACEMENT      across
    FORCE             through
    TRANSLATIONAL_REF reference;

  nature TRANSLATIONAL_VECTOR is 
    array (NATURAL range <>) of TRANSLATIONAL;

  nature TRANSLATIONAL_VELOCITY is
    VELOCITY                   across
    FORCE                      through
    TRANSLATIONAL_VELOCITY_REF reference;

  nature TRANSLATIONAL_VELOCITY_VECTOR is 
    array (NATURAL range <>) of TRANSLATIONAL_VELOCITY;

  nature ROTATIONAL is
    ANGLE          across
    TORQUE         through
    ROTATIONAL_REF reference;

  nature ROTATIONAL_VECTOR is
    array (NATURAL range <>) of ROTATIONAL;

  nature ROTATIONAL_VELOCITY is
    ANGULAR_VELOCITY        across
    TORQUE                  through
    ROTATIONAL_VELOCITY_REF reference;

  nature ROTATIONAL_VELOCITY_VECTOR is
    array (NATURAL range <>) of ROTATIONAL_VELOCITY;

  -- vector subtype declarations
  subtype DISPLACEMENT_VECTOR         is TRANSLATIONAL_VECTOR'across;
  subtype FORCE_VECTOR                is TRANSLATIONAL_VECTOR'through;
  subtype VELOCITY_VECTOR             is TRANSLATIONAL_VELOCITY_VECTOR'across;
  subtype FORCE_VELOCITY_VECTOR       is TRANSLATIONAL_VELOCITY_VECTOR'through;
  subtype ANGLE_VECTOR                is ROTATIONAL_VECTOR'across;
  subtype TORQUE_VECTOR               is ROTATIONAL_VECTOR'through;
  subtype ANGULAR_VELOCITY_VECTOR     is ROTATIONAL_VELOCITY_VECTOR'across;
  subtype TORQUE_VELOCITY_VECTOR      is ROTATIONAL_VELOCITY_VECTOR'through;
  subtype ACCELERATION_VECTOR         is REAL_VECTOR tolerance
                                            "DEFAULT_ACCELERATION";
  subtype MASS_VECTOR                 is REAL_VECTOR tolerance
                                            "DEFAULT_MASS";
  subtype STIFFNESS_VECTOR            is REAL_VECTOR tolerance
                                            "DEFAULT_STIFFNESS";
  subtype DAMPING_VECTOR              is REAL_VECTOR tolerance
                                            "DEFAULT_DAMPING";
  subtype MOMENTUM_VECTOR             is REAL_VECTOR tolerance
                                            "DEFAULT_MOMENTUM";
  subtype ANGULAR_ACCELERATION_VECTOR is REAL_VECTOR tolerance
                                            "DEFAULT_ANGULAR_ACCELERATION";
  subtype MOMENT_INERTIA_VECTOR       is REAL_VECTOR tolerance
                                            "DEFAULT_MOMENT_INERTIA";
  subtype ANGULAR_MOMENTUM_VECTOR     is REAL_VECTOR tolerance
                                            "DEFAULT_ANGULAR_MOMENTUM";
  subtype ANGULAR_STIFFNESS_VECTOR    is REAL_VECTOR tolerance
                                            "DEFAULT_ANGULAR_STIFFNESS";
  subtype ANGULAR_DAMPING_VECTOR      is REAL_VECTOR tolerance
                                            "DEFAULT_ANGULAR_DAMPING";

  -- alias declarations
  alias ANCHOR              is TRANSLATIONAL_REF;
  alias TRANSLATIONAL_V_REF is TRANSLATIONAL_VELOCITY_REF;
  alias ROTATIONAL_V_REF    is ROTATIONAL_VELOCITY_REF;
  alias TRANSLATIONAL_V     is TRANSLATIONAL_VELOCITY;
  alias ROTATIONAL_V        is ROTATIONAL_VELOCITY;

end package MECHANICAL_SYSTEMS;
