# Generated by Django 5.1.1 on 2024-11-26 04:58

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0002_alter_customuser_otp_secret'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='is_two_factor_enabled',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='otp_secret',
        ),
    ]
