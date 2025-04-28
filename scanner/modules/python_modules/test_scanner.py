def run(scan):
    print("TEST SCANNER IS RUNNING")
    scan.output = "Test scanner ran successfully"
    scan.status = 'completed'
    scan.save()
    return "Test scanner ran successfully" 