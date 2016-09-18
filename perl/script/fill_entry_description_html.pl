#!/usr/bin/env perl
use strict;
use warnings;
use utf8;
use Isuda::Web;
use Kossy::Request;

{
    package C;

    sub new {
        my ($class) = @_;
        bless {}, $class;
    }

    sub req {
        Kossy::Request->new({ HTTP_HOST => '13.78.90.210'});
    }

    1;
}

package main;

my $cnt = 0;
my $app = Isuda::Web->new;
my $c = C->new;

sub execute {
    my $ents = $app->dbh->select_all('SELECT id, description FROM entry');

    for my $ent (@$ents) {
        my $html = $app->htmlify($c, $ent->{description});
        $app->dbh->query('UPDATE entry SET description_html = ? WHERE id = ?', $html, $ent->{id});
        warn $cnt++;
    }
}

execute();
