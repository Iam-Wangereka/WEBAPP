# Generated by Django 4.2.3 on 2023-07-30 10:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('contacts', '0004_alter_contact_registration_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='contact',
            name='username',
            field=models.CharField(default='default_username', max_length=100),
        ),
    ]