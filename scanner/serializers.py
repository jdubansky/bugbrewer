from rest_framework import serializers
from .models import Asset, Scan

class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = '__all__'

class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = '__all__'

class BulkAssetSerializer(serializers.Serializer):
    assets = serializers.ListField(
        child=serializers.DictField(),  # Accepts a list of dictionaries
        allow_empty=False
    )

    def create(self, validated_data):
        assets_data = validated_data['assets']
        assets = [Asset(**data) for data in assets_data]
        return Asset.objects.bulk_create(assets)
