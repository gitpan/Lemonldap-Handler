package Lemonldap::Handler::Intrusion;

use constant DEBUG=>0;

use Apache::Constants qw(:common :response);
our %responses=(syslog=>\&syslog,
		mail=>\&mail,
		forbidden=>\&forbidden,
		);
sub syslog {
	return FORBIDDEN;
}
sub mail {
	return FORBIDDEN;
}
sub forbidden {
	return FORBIDDEN;
}
1;
__END__

=head1 NAME

Lemonldap::Handler::Intrusion - Perl subroutine to process unwanted requests on
an Apache webserver protected by a Lemonldap compatible SSO agent.

=head1 SYNOPSIS

  use Lemonldap::Handler::Intrusion;
  ...
  sub handler {
    ...
    return Lemonldap::Handler::Intrusion::syslog if(rejected_request);
    ...
  }

=head1 DESCRIPTION

Lemonldap is a collection of Perl modules written to implement a complete
solution of web single sign on (Web-SSO).

This module provides differents subroutine to process unwanted requests on an
Apache webserver protected by a lemonldap compatible SSO agent.

Those subroutines are :

=over 4

=item forbidden() (default): returns just the FORBIDDEN Apache::Constants value
without notifying anything

=item mail(): send an email to the administrator and returns FORBIDDEN

=item syslog(): generate a customize syslog record end returns FORBIDDEN

=back

=head1 SEE ALSO

Lemonldap(3), Apache::Constants(3)

http://lemonldap.sourceforge.net/

=head1 AUTHORS

=over 1

=item Eric German, E<lt>germanlinux@yahoo.frE<gt>

=item Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Eric German E<amp> Xavier Guimard

Lemonldap originaly written by Eric german who decided to publish him in 2003
under the terms of the GNU General Public License version 2.

=over 1

=item This library is under the GNU General Public License, Version 2.

=back

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 dated June, 1991.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  A copy of the GNU General Public License is available in the source tree;
  if not, write to the Free Software Foundation, Inc.,
  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=cut
