# Generated by Django 5.1.1 on 2025-03-11 10:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_sellerorder_order_address'),
    ]

    operations = [
        migrations.AddField(
            model_name='sellerorder',
            name='order_consignee',
            field=models.CharField(default='', max_length=150),
        ),
    ]
