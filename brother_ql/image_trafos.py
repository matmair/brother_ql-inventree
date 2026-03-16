from PIL import Image
import colorsys

def filtered_hsv(im: Image.Image, filter_h: int, filter_s: int, filter_v: int, default_col=(255,255,255)) -> Image.Image:
    """ https://stackoverflow.com/a/22237709/183995 """

    hsv_im = im.convert('HSV')
    H, S, V = 0, 1, 2
    hsv = hsv_im.split()
    mask_h = hsv[H].point(filter_h)
    mask_s = hsv[S].point(filter_s)
    mask_v = hsv[V].point(filter_v)

    Mdat = []
    for h, s, v in zip(mask_h.getdata(), mask_s.getdata(), mask_v.getdata()):
        Mdat.append(255 if (h and s and v) else 0)

    mask = mask_h
    mask.putdata(Mdat)

    filtered_im = Image.new("RGB", im.size, color=default_col)
    filtered_im.paste(im, None, mask)
    return filtered_im
