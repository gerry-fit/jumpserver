# Generated by Django 3.1.12 on 2021-11-02 11:22

from django.db import migrations


def create_internal_platform(apps, schema_editor):
    model = apps.get_model("assets", "Platform")
    db_alias = schema_editor.connection.alias
    type_platforms = (
        ('Windows-RDP', 'Windows', {'security': 'rdp'}),
        ('Windows-TLS', 'Windows', {'security': 'tls'}),
    )
    for name, base, meta in type_platforms:
        defaults = {'name': name, 'base': base, 'meta': meta, 'internal': True}
        model.objects.using(db_alias).update_or_create(
            name=name, defaults=defaults
        )


class Migration(migrations.Migration):

    dependencies = [
        ('assets', '0078_auto_20211014_2209'),
    ]

    operations = [
        migrations.RunPython(create_internal_platform)
    ]
