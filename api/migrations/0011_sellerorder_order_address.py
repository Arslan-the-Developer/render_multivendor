# Generated by Django 5.1.1 on 2025-03-04 09:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_product_product_sub_category'),
    ]

    operations = [
        migrations.AddField(
            model_name='sellerorder',
            name='order_address',
            field=models.TextField(default=''),
        ),
    ]
