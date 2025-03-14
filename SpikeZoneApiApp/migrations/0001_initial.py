# Generated by Django 5.1.3 on 2024-12-30 07:41

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('category_id', models.CharField(max_length=50)),
                ('category_name', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='Products',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('product_sku', models.CharField(max_length=50)),
                ('category', models.CharField(max_length=100)),
                ('inStock', models.BooleanField(default=True)),
                ('isBest', models.BooleanField(default=False)),
                ('title', models.CharField(max_length=50)),
                ('image1', models.ImageField(blank=True, null=True, upload_to='media/')),
                ('image2', models.ImageField(blank=True, null=True, upload_to='media/')),
                ('image3', models.ImageField(blank=True, null=True, upload_to='media/')),
                ('image4', models.ImageField(blank=True, null=True, upload_to='media/')),
                ('image5', models.ImageField(blank=True, null=True, upload_to='media/')),
                ('price', models.CharField(max_length=50)),
                ('max_price', models.CharField(max_length=50)),
                ('short_desc', models.CharField(max_length=500)),
                ('long_desc', models.CharField(max_length=9999)),
                ('bullet_one', models.CharField(max_length=500)),
                ('bullet_two', models.CharField(blank=True, max_length=500, null=True)),
                ('bullet_three', models.CharField(blank=True, max_length=500, null=True)),
                ('bullet_four', models.CharField(blank=True, max_length=500, null=True)),
                ('bullet_five', models.CharField(blank=True, max_length=500, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=255, unique=True, verbose_name='Email')),
                ('name', models.CharField(max_length=50)),
                ('contact', models.CharField(max_length=50)),
                ('address', models.CharField(blank=True, default='', max_length=999, null=True)),
                ('state', models.CharField(blank=True, default='', max_length=50, null=True)),
                ('city', models.CharField(blank=True, default='', max_length=50, null=True)),
                ('postalcode', models.CharField(blank=True, default='', max_length=10, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
