# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.utils import timezone

class UserCreateForm(UserCreationForm):
    email = forms.CharField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        user = super(UserCreateForm, self).save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user

class UploadFile(models.Model):
    userID = models.ForeignKey(User, verbose_name='userId',on_delete=models.CASCADE,blank=True,null=True)
    state = models.IntegerField(verbose_name='stateCode')
    filename = models.CharField(max_length=200, verbose_name='filename')
    filePath = models.CharField(max_length=500, verbose_name='filePath',blank=True,null=True)

    class Meta:
        verbose_name = 'uploadFile'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.filename

class DownloadFile(models.Model):
    fileId = models.ForeignKey(UploadFile, verbose_name='file',on_delete=models.CASCADE,blank=True,null=True)
    userID = models.ForeignKey(User, verbose_name='userId',on_delete=models.CASCADE,blank=True,null=True)
    state = models.IntegerField(verbose_name='stateCode')
    nro = models.CharField(max_length=500, verbose_name='nro',blank=True,null=True)
    nro_original = models.CharField(max_length=500, verbose_name='nro_original', blank=True, null=True)

    class Meta:
        verbose_name = 'downloadFile'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.fileId

class Receipt(models.Model):
    fileId = models.ForeignKey(UploadFile, verbose_name='file',on_delete=models.CASCADE,blank=True,null=True)
    userId = models.ForeignKey(User,verbose_name='userId',on_delete=models.CASCADE,blank=True,null=True)
    nrr = models.CharField(max_length=500, verbose_name='nrr',blank=True,null=True)
    nrr_originial = models.CharField(max_length=500, verbose_name='nrr_originial', blank=True, null=True)

    class Meta:
        verbose_name = 'Receipt'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.fileId