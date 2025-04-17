from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.postgres.search import SearchVector
from .models import Product
from django.db.models import F


@receiver(post_save, sender=Product)
def update_search_vector(sender, instance, created, **kwargs):

    """
    Updates the search_vector field automatically before saving a Product instance.
    """

    if created:

        Product.objects.filter(pk=instance.pk).update(
            search_vector=SearchVector("product_keywords")
        )
