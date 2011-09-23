#!/usr/bin/env perl
use Mojo::Base -strict;
use lib '../lib';
use Mojolicious::Lite;
plugin 'CSRFProtect';

any '/' => sub {
  my $self = shift;
  $self->render('index');
};


app->start;

__DATA__
@@ index.html.ep
    <%= javascript '/js/jquery.js' %>
 <%= form_for '/' => (method => 'post') => begin %>
    <%= text_field 'first_name' %>
    <%= submit_button %>
 <% end %>
 
 <%= jquery_ajax_csrf_protection %>
