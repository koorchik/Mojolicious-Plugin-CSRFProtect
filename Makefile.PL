#!/usr/bin/env perl

use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME         => 'Mojolicious::Plugin::CSRFProtect',
  VERSION_FROM => 'lib/Mojolicious/Plugin/CSRFProtect.pm',
  AUTHOR       => 'A Good Programmer <nospam@cpan.org>',
  PREREQ_PM    => {'Mojolicious' => '1.90'},
  test         => {TESTS => 't/*.t'}
);
