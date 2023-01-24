# Generated by Django 3.2.16 on 2023-01-18 16:42

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hopskotch_auth', '0009_scramexchange_began'),
    ]

    operations = [
        migrations.AddField(
            model_name='kafkatopic',
            name='archivable',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='kafkatopic',
            name='max_message_bytes',
            field=models.BigIntegerField(default=1000012, validators=[django.core.validators.MinValueValidator(1024), django.core.validators.MaxValueValidator(104857600)]),
        ),
        migrations.AddField(
            model_name='kafkatopic',
            name='n_partitions',
            field=models.IntegerField(default=2, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(128)]),
        ),
        migrations.AddField(
            model_name='kafkatopic',
            name='retention_bytes',
            field=models.BigIntegerField(default=-1, validators=[django.core.validators.MinValueValidator(-1), django.core.validators.MaxValueValidator(1099511627776)]),
        ),
        migrations.AddField(
            model_name='kafkatopic',
            name='retention_ms',
            field=models.BigIntegerField(default=2422800000, validators=[django.core.validators.MinValueValidator(1000), django.core.validators.MaxValueValidator(31536000000)]),
        ),
    ]
