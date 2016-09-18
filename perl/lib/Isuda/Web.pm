package Isuda::Web;
use 5.014;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Encode qw/encode_utf8/;
use POSIX qw/ceil/;
use Furl;
use JSON::XS qw/decode_json/;
use String::Random qw/random_string/;
use Digest::SHA1 qw/sha1_hex/;
use URI::Escape qw/uri_escape_utf8/;
use Text::Xslate::Util qw/html_escape/;
use List::Util qw/min max/;

state $ua = Furl->new;

sub config {
    state $conf = {
        dsn           => $ENV{ISUDA_DSN}         // 'dbi:mysql:db=isuda',
        db_user       => $ENV{ISUDA_DB_USER}     // 'root',
        db_password   => $ENV{ISUDA_DB_PASSWORD} // '',
        isupam_origin => $ENV{ISUPAM_ORIGIN}     // 'http://localhost:5050',
    };
    my $key = shift;
    my $v = $conf->{$key};
    unless (defined $v) {
        die "config value of $key undefined";
    }
    return $v;
}

sub dbh {
    my ($self) = @_;
    return $self->{dbh} //= DBIx::Sunny->connect(config('dsn'), config('db_user'), config('db_password'), {
        Callbacks => {
            connected => sub {
                my $dbh = shift;
                $dbh->do(q[SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY']);
                $dbh->do('SET NAMES utf8mb4');
                return;
            },
        },
    });
}

sub users {
    my ($self) = @_;

    state $users =  $self->dbh->select_all('SELECT * FROM user');
}

sub user_by_id {
    my ($self, $id) = @_;

    state $user_by_id = { map { $_->{id} => $_ } @{$self->users} };

    return $user_by_id->{$id};
}

sub user_by_name {
    my ($self, $name) = @_;

    state $user_by_name = { map { $_->{name} => $_ } @{$self->users} };

    return $user_by_name->{$name};
}

filter 'set_name' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $user_id = $c->env->{'psgix.session'}->{user_id};
        if ($user_id) {
            $c->stash->{user_id} = $user_id;
            $c->stash->{user_name} = $self->user_by_id($user_id)->{name};
            $c->halt(403) unless defined $c->stash->{user_name};
        }
        $app->($self,$c);
    };
};

filter 'authenticate' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        $c->halt(403) unless defined $c->stash->{user_id};
        $app->($self,$c);
    };
};

get '/initialize' => sub {
    my ($self, $c)  = @_;

    # initialize isuda db
    $self->dbh->query(q[
        DELETE FROM entry WHERE id > 7101
    ]);
    $self->dbh->query(q[
        ALTER TABLE entry AUTO_INCREMENT = 7102
    ]);

    # initialize 元isutar db
    $self->dbh->query('TRUNCATE star');
};

get '/' => [qw/set_name/] => sub {
    my ($self, $c)  = @_;

    my $PER_PAGE = 10;
    my $page = $c->req->parameters->{page} || 1;

    my $entries = $self->dbh->select_all(qq[
        SELECT id FROM entry
        ORDER BY updated_at DESC
        LIMIT $PER_PAGE
        OFFSET @{[ $PER_PAGE * ($page-1) ]}
    ]);
    my @entry_ids = map { $_->{id} } @$entries;
    $entries = $self->dbh->select_all(qq[
        SELECT id, author_id, keyword, description_html, updated_at, created_at, keyword_length FROM entry
        WHERE id IN (?)
    ], \@entry_ids);

    my $keywords = [map { $_->{keyword} } @$entries];
    my $stars_by_keyword = $self->load_starts_by_keyword($keywords);
    foreach my $entry (@$entries) {
        $entry->{html} = $entry->{description_html};
        $entry->{stars} = $stars_by_keyword->{$entry->{keyword}};
    }

    my $total_entries = $self->dbh->select_one(q[
        SELECT MAX(id) FROM entry
    ]);
    my $last_page = ceil($total_entries / $PER_PAGE);
    my @pages = (max(1, $page-5)..min($last_page, $page+5));

    $c->render('index.tx', { entries => $entries, page => $page, last_page => $last_page, pages => \@pages });
};

get 'robots.txt' => sub {
    my ($self, $c)  = @_;
    $c->halt(404);
};

post '/keyword' => [qw/set_name authenticate/] => sub {
    my ($self, $c) = @_;
    my $keyword = $c->req->parameters->{keyword};
    unless (length $keyword) {
        $c->halt(400, q('keyword' required));
    }
    my $user_id = $c->stash->{user_id};
    my $description = $c->req->parameters->{description};

    if (is_spam_contents($description) || is_spam_contents($keyword)) {
        $c->halt(400, 'SPAM!');
    }

    # 自分のdescription作る
    my $description_html = $self->htmlify($c, $keyword, $description);

    $self->dbh->query(q[
        INSERT INTO entry (author_id, keyword, description, description_html, created_at, updated_at, keyword_length)
        VALUES (?, ?, ?, ?, NOW(), NOW(), ?)
        ON DUPLICATE KEY UPDATE
        author_id = ?, keyword = ?, description = ?, description_html = ?, updated_at = NOW()
    ], $user_id, $keyword, $description, $description_html, length($keyword), $user_id, $keyword, $description, $description_html);

    # 他のentryを更新
    $self->htmlify_others($c, $keyword);

    $c->redirect('/');
};

get '/register' => [qw/set_name/] => sub {
    my ($self, $c)  = @_;
    $c->render('authenticate.tx', {
        action => 'register',
    });
};

post '/register' => sub {
    my ($self, $c) = @_;

    my $name = $c->req->parameters->{name};
    my $pw   = $c->req->parameters->{password};
    $c->halt(400) if $name eq '' || $pw eq '';

    my $user_id = register($self->dbh, $name, $pw);

    $c->env->{'psgix.session'}->{user_id} = $user_id;
    $c->redirect('/');
};

sub register {
    my ($dbh, $user, $pass) = @_;

    my $salt = random_string('....................');
    $dbh->query(q[
        INSERT INTO user (name, salt, password, created_at)
        VALUES (?, ?, ?, NOW())
    ], $user, $salt, sha1_hex($salt . $pass));

    return $dbh->last_insert_id;
}

get '/login' => [qw/set_name/] => sub {
    my ($self, $c)  = @_;
    $c->render('authenticate.tx', {
        action => 'login',
    });
};

post '/login' => sub {
    my ($self, $c) = @_;

    my $name = $c->req->parameters->{name};
    my $row = $self->user_by_name($name);
    if (!$row || $row->{password} ne sha1_hex($row->{salt}.$c->req->parameters->{password})) {
        $c->halt(403)
    }

    $c->env->{'psgix.session'}->{user_id} = $row->{id};
    $c->redirect('/');
};

get '/logout' => sub {
    my ($self, $c)  = @_;
    $c->env->{'psgix.session'} = {};
    $c->redirect('/');
};

get '/keyword/:keyword' => [qw/set_name/] => sub {
    my ($self, $c) = @_;
    my $keyword = $c->args->{keyword} // $c->halt(400);

    my $entry = $self->dbh->select_row(qq[
        SELECT id, author_id, keyword, description_html, updated_at, created_at, keyword_length FROM entry
        WHERE keyword = ?
    ], $keyword);
    $c->halt(404) unless $entry;
    $entry->{html} = $entry->{description_html};
    $entry->{stars} = $self->load_stars($entry->{keyword});

    $c->render('keyword.tx', { entry => $entry });
};

post '/keyword/:keyword' => [qw/set_name authenticate/] => sub {
    my ($self, $c) = @_;
    my $keyword = $c->args->{keyword} or $c->halt(400);
    $c->req->parameters->{delete} or $c->halt(400);

    $c->halt(404) unless $self->dbh->select_row(qq[
        SELECT * FROM entry
        WHERE keyword = ?
    ], $keyword);

    $self->dbh->query(qq[
        DELETE FROM entry
        WHERE keyword = ?
    ], $keyword);
    $c->redirect('/');
};

post '/stars' => sub {
    my ($self, $c) = @_;
    my $keyword = $c->req->parameters->{keyword};

    my $entry = $self->dbh->select_row(qq[
        SELECT id FROM entry
        WHERE keyword = ?
    ], $keyword);
    unless ($entry) {
        $c->halt(404);
    }

    $self->dbh->query(q[
        INSERT INTO star (keyword, user_name, created_at)
        VALUES (?, ?, NOW())
    ], $keyword, $c->req->parameters->{user});

    $c->render_json({
        result => 'ok',
    });
};

sub create_re {
    my ($self, $keyword) = @_;

    my $keywords = $self->dbh->select_all(qq[
        SELECT keyword FROM entry ORDER BY keyword_length DESC
    ]);
    push @$keywords, +{ keyword => $keyword };
    my $re = join '|', map { quotemeta $_->{keyword} } @$keywords;

    return $re;
}

sub htmlify_with_re {
    my ($self, $c, $content, $re) = @_;

    return '' unless defined $content;

    my %kw2sha;
    $content =~ s{($re)}{
        my $kw = $1;
        $kw2sha{$kw} = "isuda_" . sha1_hex(encode_utf8($kw));
    }eg;
    $content = html_escape($content);
    while (my ($kw, $hash) = each %kw2sha) {
        my $url = 'http://'.$c->req->env->{HTTP_HOST}.'/keyword/'.uri_escape_utf8($kw);
        my $link = sprintf '<a href="%s">%s</a>', $url, html_escape($kw);
        $content =~ s/$hash/$link/g;
    }
    $content =~ s{\n}{<br \/>\n}gr;
}

sub htmlify {
    my ($self, $c, $keyword, $content) = @_;

    my $re = $self->create_re($keyword);
    return $self->htmlify_with_re($c, $content, $re);
}

sub htmlify_others {
    my ($self, $c, $keyword) = @_;

    my $entries = $self->dbh->select_all('SELECT id, description FROM entry WHERE MATCH (description) AGAINST (? IN NATURAL LANGUAGE MODE)', $keyword);
    my $htmlify_re = $self->create_re($keyword);

    for my $entry (@$entries) {
        my $html = $self->htmlify_with_re($c, $entry->{description}, $htmlify_re);
        $self->dbh->query('UPDATE entry SET description_html = ? WHERE id = ?', $html, $entry->{id});
    }
}

sub load_stars {
    my ($self, $keyword) = @_;

    my $stars = $self->dbh->select_all(q[
        SELECT * FROM star WHERE keyword = ?
    ], $keyword);

    return $stars;
}

sub load_starts_by_keyword {
    my ($self, $keywords) = @_;

    my $stars = $self->dbh->select_all(q[
        SELECT keyword, user_name FROM star WHERE keyword IN (?)
    ], $keywords);

    my $ret = {};

    for my $star (@$stars) {
        $ret->{$star->{keyword}} //= [];
        push @{$ret->{$star->{keyword}}}, $star;
    }

    return $ret;
}

sub is_spam_contents {
    my $content = shift;
    my $res = $ua->post(config('isupam_origin'), [], [
        content => encode_utf8($content),
    ]);
    my $data = decode_json $res->content;
    !$data->{valid};
}

1;
