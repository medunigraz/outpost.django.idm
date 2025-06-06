# Generated by Django 2.2.28 on 2025-06-05 11:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        (
            "idm",
            "0002_extractor_incident_incidentresponder_jiraresponder_kaduusource_languagemodelextractor_mailresponder_",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="mailresponderrecipient",
            name="responder",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="recipients",
                to="idm.MailResponder",
            ),
        ),
    ]
