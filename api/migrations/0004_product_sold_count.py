# Generated by Django 5.1.1 on 2025-02-09 15:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_alter_product_search_vector'),
    ]

    operations = [
        migrations.AddField(
            model_name='product',
            name='sold_count',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
