package Mojolicious::Plugin::CSRFProtect;
use strict;
use warnings;
use Carp qw/croak/;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util qw/md5_sum/;
use Mojo::ByteStream qw/b/;

our $VERSION = '0.16';

sub register {
    my ( $self, $app, $conf ) = @_;

    # On error callback
    my $on_error;
    if ( $conf->{on_error} && ref( $conf->{on_error} ) eq 'CODE' ) {
        $on_error = $conf->{on_error};
    } else {
        $on_error = sub { shift->render( status => 403, text => "Forbidden!" ) };
    }

    # Replace "form_for" helper
    my $original_form_for = delete $app->renderer->helpers->{form_for};
    croak qq{Cannot find helper "form_for". Please, load plugin "TagHelpers" before}
      unless $original_form_for;

    $app->helper(
        form_for => sub {
            my $c = shift;
            if ( defined $_[-1] && ref( $_[-1] ) eq 'CODE' ) {
                my $cb = $_[-1];
                $_[-1] = sub {
                    $app->hidden_field( 'csrftoken' => $self->_csrftoken($c) ) . $cb->();
                };
            }
            return $app->$original_form_for(@_);
        }
    );

    # Add "csrftoken" helper
    $app->helper( csrftoken => sub { $self->_csrftoken( $_[0] ) } );

    # Add "is_valid_csrftoken" helper
    $app->helper( is_valid_csrftoken => sub { $self->_is_valid_csrftoken( $_[0] ) } );

    # Add "jquery_ajax_csrf_protection" helper
    $app->helper(
        jquery_ajax_csrf_protection => sub {
            my $js = $self->_view_meta_csrftoken( $_[0] );
            $js .= $self->_view_jquery_csrftoken( $_[0] );
            b($js);
        }
    );

    # Add "meta_csrf_protection" helper
    $app->helper(
        meta_csrf_protection => sub {
            my $js = $self->_view_meta_csrftoken( $_[0] );
            b($js);
        }
    );

    # Add "jquery_csrf_protection" helper
    $app->helper(
        jquery_csrf_protection => sub {
            my $js = $self->_view_jquery_csrftoken( $_[0] );
            b($js);
        }
    );

    # Add "jquery_defered_csrf_protection" helper
    $app->helper(
        jquery_defered_csrf_protection => sub {
            my $js = $self->_view_jquery_csrftoken( $_[0], 'defer' );
            b($js);
        }
    );

    # input check
    $app->hook(
        before_routes => sub {
            my ($c) = @_;

            my $request_token = $c->req->param('csrftoken');

            #my $is_ajax = ( $c->req->headers->header('X-Requested-With') || '' ) eq 'XMLHttpRequest';

            if ( $c->req->method !~ m/^(?:GET|HEAD|OPTIONS)$/ && !$self->_is_valid_csrftoken($c) ) {
                my $path = $c->tx->req->url->to_abs->to_string;
                $c->app->log->debug("CSRFProtect: Wrong CSRF protection token for [$path]!");

                $on_error->($c);
                return;
            }

            return 1;
        }
    );

}

sub _view_meta_csrftoken {
    my ( $self, $c ) = @_;

    return '<meta name="csrftoken" content="' . $self->_csrftoken($c) . '"/>';
}

sub _view_jquery_csrftoken {
    my ( $self, $c, $defer_or_async ) = @_;

    $defer_or_async = ($defer_or_async) ? " $defer_or_async " : ' ';

    my $js = q!<script%stype="text/javascript">!;
    $js .= q! jQuery(document).ajaxSend(function(e, xhr, options) { !;
    $js .= q!    var token = jQuery("meta[name='csrftoken']").attr("content");!;
    $js .= q! xhr.setRequestHeader("X-CSRF-Token", token);!;
    $js .= q! });</script>!;

    return sprintf( $js => $defer_or_async );
}

sub _is_valid_csrftoken {
    my ( $self, $c ) = @_;

    my $valid_token = $c->session('csrftoken');
    my $form_token = $c->req->headers->header('X-CSRF-Token') || $c->param('csrftoken');
    unless ( $valid_token && $form_token && $form_token eq $valid_token ) {
        return 0;
    }

    return 1;
}

sub _csrftoken {
    my ( $self, $c ) = @_;

    return $c->session('csrftoken') if $c->session('csrftoken');

    my $token = md5_sum( md5_sum( time() . {} . rand() . $$ ) );

    $c->session( 'csrftoken' => $token );
    return $token;
}

1;

__END__

=head1 NAME

Mojolicious::Plugin::CSRFProtect - Fully protects you from CSRF attacks

=head1 SYNOPSIS

    # Mojolicious
    $self->plugin('CSRFProtect');

    # Mojolicious::Lite
    plugin 'CSRFProtect';

    # Use "form_for" helper and all your html forms will have CSRF protection token

    <%= form_for login => (method => 'post') => begin %>
           <%= text_field 'first_name' %>
           <%= submit_button %>
    <% end %>


    # Place jquery_ajax_csrf_protection helper to your layout template
    # and all non GET/HEAD/OPTIONS  AJAX requests will have CSRF protection token (requires JQuery, added the cloudflare in the example, replace it by yours)

	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
		<%= jquery_ajax_csrf_protection %>
		</head>
	<body><%= content %></body>
	</html>

	# Or, place the meta_csrf_protection in the head of your layout template
	# and place the jquery_csrf_protection after the body tag (was the model before using defer or async on scripts)
	# (requires JQuery for the second tag, added the cloudflare in the example, replace it by yours)

	<!DOCTYPE html>
	<html>
	<head>
	<%= meta_csrf_protection %>
	</head>
	<body><%= content %></body>
	<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js" crossorigin="anonymous"></script>
	<%= jquery_ajax_csrf_protection %>
	</html>

	# Or, defer javascript after loading the document L<https://developers.google.com/speed/docs/insights/BlockingJS?hl=en>

	<!DOCTYPE html>
	<html>
	<head>
	<%= meta_csrf_protection %>
	<script defer src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js" crossorigin="anonymous"></script>
	<%= jquery_defered_ajax_csrf_protection %>
	</head>
	<body><%= content %></body>
	</html>

    # Custom error handling

    $self->plugin('CSRFProtect', on_error => sub {
        my $c = shift;
        # Do whatever you want here
        # ...
    });

=head1 DESCRIPTION

L<Mojolicious::Plugin::CSRFProtect> is a L<Mojolicious> plugin which fully protects you from CSRF attacks.

It does following things:

1. Adds a hidden input (with name 'csrftoken') with CSRF protection token to every form
(works only if you use C<form_for> helper from Mojolicious::Plugin::TagHelpers.)

2. Adds the header "X-CSRF-Token" with CSRF token to every AJAX request (works with JQuery only)

3. Rejects all non GET/HEAD/OPTIONS requests without the correct CSRF protection token.


If you want protect your GET/HEAD/OPTIONS requests then you can do it manually

In template: <a href="/delete_user/123/?csrftoken=<%= csrftoken %>">

In controller: $self->is_valid_csrftoken()

=head1 CONFIG

=head2 C<on_error>

You can pass custom error handling callback. For example

    $self->plugin('CSRFProtect', on_error => sub {
        my $c = shift;
        $c->render(template => 'error_403', status => 403 );
    });

=head1 HELPERS

=head2 C<form_for>

This helper overrides the C<form_for> helper from Mojolicious::Plugin::TagHelpers

and adds hidden input with CSRF protection token.

=head2 C<jquery_ajax_csrf_protection>

This helper adds CSRF protection headers to all JQuery AJAX requests, kept by compatibility.

You should add <%= jquery_ajax_csrf_protection %> in head of your HTML page.

=head2 C<meta_csrf_protection>

This helper adds CSRF protection headers to all JQuery AJAX requests.

You should add <%= meta_csrf_protection %> in head of your HTML page.

=head2 C<jquery_csrf_protection>

This helper adds CSRF protection headers to all JQuery AJAX requests.

You should add <%= jquery_ajax_csrf_protection %> after your jquery script instance on your HTML page.

=head2 C<jquery_defered_csrf_protection>

This helper adds a defered CSRF protection headers to all JQuery AJAX requests.

You should add <%= jquery_defered_ajax_csrf_protection %> after your jquery defered script instance in the head tag on your HTML page.

=head2 C<csrftoken>

returns  CSRF Protection token.

In templates <%= csrftoken %>

In controller $self->csrftoken;

=head2 C<is_valid_csrftoken>

With this helper you can check $csrftoken manually. It will take $csrftoken from $c->param('csrftoken');

$self->is_valid_csrftoken() will return 1 or 0

=head1 AUTHOR

Viktor Turskyi <koorchik@cpan.org>

=head1 BUGS

Please report any bugs or feature requests to C<bug-mojolicious-plugin-csrfprotect at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Mojolicious-Plugin-CSRFProtect>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

Also you can report bugs to Github L<https://github.com/koorchik/Mojolicious-Plugin-CSRFProtect/>

=head1 SEE ALSO

=over 4

=item L<Mojolicious::Plugin::CSRFDefender>

This plugin followes the same aproach but it works in different manner.

It will parse your response body searching for '<form>' tag and then will insert CSRF token there.

=back

=head1 LICENSE AND COPYRIGHT

Copyright 2011 Viktor Turskyi

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut
