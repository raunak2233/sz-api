# Generated by Django 5.1.3 on 2025-07-12 08:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SpikeZoneApiApp', '0004_blog'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailOTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('otp', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
