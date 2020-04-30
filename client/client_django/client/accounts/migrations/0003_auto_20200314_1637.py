# Generated by Django 3.0.4 on 2020-03-14 16:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_message_created_time'),
    ]

    operations = [
        migrations.CreateModel(
            name='DownloadFile',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fileId', models.IntegerField(verbose_name='fileId')),
                ('userId', models.IntegerField(verbose_name='userId')),
                ('state', models.IntegerField(verbose_name='stateCode')),
            ],
            options={
                'verbose_name': 'downloadFile',
                'verbose_name_plural': 'downloadFile',
            },
        ),
        migrations.CreateModel(
            name='Receipt',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fileId', models.IntegerField(verbose_name='fileId')),
                ('uploadUserId', models.IntegerField(verbose_name='upLoadUserId')),
                ('downloadUserId', models.IntegerField(verbose_name='downLoadUserId')),
            ],
            options={
                'verbose_name': 'Receipt',
                'verbose_name_plural': 'Receipt',
            },
        ),
        migrations.CreateModel(
            name='UploadFile',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userId', models.IntegerField(verbose_name='userId')),
                ('state', models.IntegerField(verbose_name='stateCode')),
                ('filename', models.CharField(max_length=200, verbose_name='filename')),
            ],
            options={
                'verbose_name': 'uploadFile',
                'verbose_name_plural': 'uploadFile',
            },
        ),
        migrations.DeleteModel(
            name='Message',
        ),
    ]