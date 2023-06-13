
#include<stdio.h>
void quickSort(long *numbers, int n, int low, int high)
{
  if(n >= 0){
    quickSort(numbers, -1, 0, n-1);
  }
  else{
    if (low < high) {
      long pivot = numbers[high];
      int i = (low - 1);
      for (int j = low; j <= high - 1; j++) {
        if (numbers[j] < pivot) {
          i++;
          long tmp = numbers[i];
          numbers[i] = numbers[j];
          numbers[j] = tmp;
        }
      }
      long tmp = numbers[i+1];
      numbers[i+1] = numbers[high];
      numbers[high] = tmp;
      quickSort(numbers, -1, low, i);
      quickSort(numbers, -1, i+2, high);
    }
  }
}
int main()
{
    long numbers[] = { 1, 1, 1, 1};
    int n = sizeof(numbers) / sizeof(numbers[0]);
   
    // Function call
    quickSort(numbers, n, 0, n - 1);
    printf("Sorted numbersay: \n");
    for (int i = 0; i < n; i++)
        printf("%ld ", numbers[i]);
    return 0;
}