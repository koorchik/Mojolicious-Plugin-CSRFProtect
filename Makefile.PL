#!/usr/bin/env perl

use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Mojolicious::Plugin::CSRFProtect',
    VERSION_FROM => 'lib/Mojolicious/Plugin/CSRFProtect.pm',
    ABSTRACT_FROM => 'lib/Mojolicious/Plugin/CSRFProtect.pm',
    AUTHOR       => 'Viktor Turskyi <koorchik@cpan.org>',
    PREREQ_PM    => { 'Mojolicious' => '1.90' },
    dist         => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Mojolicious-Plugin-CSRFProtect-*' },
    test  => { TESTS => 't/*.t' },
);
