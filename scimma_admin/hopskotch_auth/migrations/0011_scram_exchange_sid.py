from django.db import migrations, models
import hopskotch_auth.models

def set_sids(apps, schema_editor):
    SCRAMExchange = apps.get_model("hopskotch_auth", "scramexchange")
    for ex in SCRAMExchange.objects.all():
        ex.sid = hopskotch_auth.models.generate_scram_sid()
        ex.save(update_fields=["sid"])

class Migration(migrations.Migration):

    dependencies = [
        ('hopskotch_auth', '0010_add_topic_settings'),
    ]

    operations = [
    	# Add the new field, allowing null values for any existing entries
    	# We set no default because generate_scram_sid cannot run when the sid column doesn't yet exist
        migrations.AddField(
            model_name='scramexchange',
            name='sid',
            field=models.CharField(max_length=64, null=True),
        ),
        # Next, we assign a sid value for every existing record
        migrations.RunPython(set_sids, reverse_code=migrations.RunPython.noop),
        # Finally, we mark the column as being expected to be unique, and configure the default
        migrations.AlterField(
            model_name="scramexchange",
            name="sid",
            field=models.CharField(max_length=64, null=False, default=hopskotch_auth.models.generate_scram_sid, unique=True),
        ),
    ]
