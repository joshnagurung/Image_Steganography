from django import forms

class GenerateQRForm(forms.Form):
    text = forms.CharField(widget=forms.Textarea(attrs={'rows': 3}), label="Text to encrypt")
    password = forms.CharField(widget=forms.PasswordInput(), label="Password")

class DecryptForm(forms.Form):
    token = forms.CharField(widget=forms.Textarea(attrs={'rows': 3}), label="Encrypted Token")
    password = forms.CharField(widget=forms.PasswordInput(), label="Password")
