"""
Management command to setup default roles
"""
from django.core.management.base import BaseCommand
from registration.utils import get_or_create_roles


class Command(BaseCommand):
    help = 'Setup default roles for the system'
    
    def handle(self, *args, **options):
        """Setup default roles"""
        try:
            get_or_create_roles()
            self.stdout.write(
                self.style.SUCCESS('Successfully created default roles')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating roles: {e}')
            )
