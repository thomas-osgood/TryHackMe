outfilename="password-list.txt"
passbases=["Fall","Winter","Spring","Summer"]
years=["2021","2022","2023"]
extras=["!","@","#","$","%","^","&","*","(",")"]

with open(outfilename,"w") as fptr:
    for base in passbases:
        for year in years:
            for extra in extras:
                fptr.write(f"{base}{year}{extra}\n")

