# Generated by Django 5.2 on 2025-04-18 11:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='scan_type',
            field=models.CharField(default='Full Scan', max_length=50),
        ),
    ]
