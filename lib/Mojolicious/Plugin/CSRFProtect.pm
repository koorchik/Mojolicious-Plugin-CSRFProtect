package Mojolicious::Plugin::CSRFProtect;
use strict;
use warnings;
use Carp qw/croak/;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util qw/md5_sum/;
use Mojo::ByteStream qw/b/;

our $VERSION = '0.01';

sub register {
    my ( $self, $app ) = @_;
    my $original_form_for = $app->renderer->helpers->{form_for};
    croak qq{Cannot find helper "form_for". Please, load plugin "TagHelpers" before}
        unless $original_form_for;

    # Replace "form_for" helper
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
        } );

    # Add "csrftoken" helper
    $app->helper( csrftoken => sub { $self->_csrftoken( $_[0] ) } );

    # Add "is_valid_csrftoken" helper
    $app->helper( is_valid_csrftoken => sub { $self->_is_valid_csrftoken( $_[0] ) } );

    # Add "jquery_ajax_csrf_protection" helper
    $app->helper(
        jquery_ajax_csrf_protection => sub {
            my $js = '<meta name="csrftoken" content="' . $self->_csrftoken( $_[0] ) . '"/>';
            $js .= q!<script type="text/javascript">!;
            $js .= q! $(document).ajaxSend(function(e, xhr, options) { !;
            $js .= q!    var token = $("meta[name='csrftoken']").attr("content");!;
            $js .= q! xhr.setRequestHeader("X-CSRF-Token", token);!;
            $js .= q! });</script>!;

            b($js);
        } );

    # input check
    $app->hook(
        after_static_dispatch => sub {
            my ($c) = @_;
            my $request_token = $c->req->param('csrftoken');
            my $is_ajax = ( $c->req->headers->header('X-Requested-With') || '' ) eq 'XMLHttpRequest';
            if ( ( $is_ajax || $c->req->method ne 'GET' ) && !$self->_is_valid_csrftoken($c) ) {
                $c->render(
                    status => 403,
                    text   => "Wrong CSRF protection token!",
                );
                return;
            }

            return 1;
        } );

}

sub _is_valid_csrftoken {
    my ( $self, $c ) = @_;
    my $valid_token = $c->session('csrftoken');
    my $form_token = $c->req->headers->header('X-CSRF-Token') || $c->req->param('csrftoken');

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

Mojolicious::Plugin::CSRFProtect - Mojolicious Plugin

=head1 SYNOPSIS

  # Mojolicious
  $self->plugin('CSRFProtect');

  # Mojolicious::Lite
  plugin 'CSRFProtect';

=head1 DESCRIPTION

L<Mojolicious::Plugin::CSRFProtect> is a L<Mojolicious> plugin.

=head1 METHODS

L<Mojolicious::Plugin::CSRFProtect> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 C<register>

  $plugin->register;

Register plugin in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicio.us>.

=cut
