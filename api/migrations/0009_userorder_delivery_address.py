# Generated by Django 5.1.1 on 2025-02-26 06:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_userdeliveryaddress_is_default'),
    ]

    operations = [
        migrations.AddField(
            model_name='userorder',
            name='delivery_address',
            field=models.TextField(default=''),
        ),
    ]
