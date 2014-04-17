#!/usr/bin/perl
######################################################################
#
# This is a utility for "stringifying" a text file so that it may
# be included as a string literal within a Java source file.
#
# I use this to stringify a seeds.json file for inclusion in the
# unit tests.
#
# - David Simmons, 2014-04-16
#
######################################################################

use strict;
use warnings;

our $LINE_LENGTH = 88;
our $NORMAL_INDENT = 8;
our $CONTINUATION_INDENT = 8;

sub out {
    my ($_,$continuation,$eol) = @_;
    my $indent;
    my $newline;
    if ($continuation) {
        $indent = " "x($NORMAL_INDENT+$CONTINUATION_INDENT);
    } else {
        $indent = " "x($NORMAL_INDENT);
    }
    if ($eol) {
        $newline = "\\n";
    } else {
        $newline = "";
    }
    print $indent."\"$_".$newline."\"+\n";
}

while (<>) {
    chomp;
    s/\"/\\\"/g;

    my @lines;
    my $ll = $LINE_LENGTH;
    while ($_) {
        my $line = substr($_,0,$ll);
        if (length($_)>=$ll) {
            $_ = substr($_,$ll);
        } else {
            $_ = "";
        }
        push(@lines, $line);
        $ll = $LINE_LENGTH - $CONTINUATION_INDENT;
    }

    for (my $i=0; $i<scalar(@lines); $i++) {
        out $lines[$i], ($i>0), ($i==(scalar(@lines)-1));
    }
}

