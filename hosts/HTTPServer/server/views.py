from django.http import HttpResponse
from server.models import Stock
from django.views.decorators.csrf import csrf_exempt

from django.db import transaction
from json import dumps

# Create your views here.
import mmap

# Define the size of the memory-mapped file
file_size = 1024 * 1024 * 32  # Size in bytes (1 KB for this example)

# Create a new file (or open an existing one)
filename = "data/mmap_file.dat"

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def update_counters(request):
    global true_negatives, false_negatives

    if get_client_ip(request) == "10.0.2.2":
        false_negatives += 1
    else:
        true_negatives += 1

    with open("data/negatives.json", "w") as file:
        file.write(dumps({
            "TrueNegatives": true_negatives,
            "FalseNegatives": false_negatives
        }))

true_negatives = 0
false_negatives = 0

def index(request):
    # Simulate loading all the stocks from memory and constructing a JSON response
    # By reading a memory mapped file
    update_counters(request)

    with open(filename, "r+b") as f:
        mm = mmap.mmap(f.fileno(), file_size)
        mm.read()
        mm.close()

    return HttpResponse("", status=200)

@csrf_exempt
def buy_stock(request, stock):
    update_counters(request)

    try:
        with transaction.atomic():
            stocks = Stock.objects.get(name = stock)
            stocks.price *= 1.1

            bought = 0
            if request.POST["Quantity"] > stocks.quantity:
                bought = stocks.quantity
                stocks.quantity = 0
            else:
                stocks.quantity -= request.POST["Quantity"]
                bought = request.POST["Quantity"]
            stocks.save()
            return HttpResponse(f"Bought stocks: {bought}", status=200)

    except Stock.DoesNotExist:
        return HttpResponse("", status=404)
    
@csrf_exempt
def sell_stock(request, stock):
    update_counters(request)

    try:
        with transaction.atomic():
            stocks = Stock.objects.get(name = stock)
            stocks.price /= 1.1
            stocks.quantity += request.POST["Quantity"]
            stocks.save()
    
    except Stock.DoesNotExist:
        with transaction.atomic():
            stocks = Stock(
                name = stock,
                price = 1.0,
                quantity = request.POST["Quantity"])
            stocks.save()
    
    return HttpResponse("", status=200)