# Generated by Django 3.2.13 on 2022-05-19 09:35

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('rest_authtoken', '0002_auto_20200822_1320'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('hopskotch_auth', '0007_scramexchange'),
    ]

    operations = [
        migrations.AlterField(
            model_name='kafkatopic',
            name='name',
            field=models.CharField(max_length=249),
        ),
        migrations.CreateModel(
            name='RESTAuthToken',
            fields=[
                ('authtoken_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='rest_authtoken.authtoken')),
                ('held_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
            bases=('rest_authtoken.authtoken',),
        ),
    ]
